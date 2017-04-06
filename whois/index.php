<?php
$domain = $_GET['domain'];
$whoisservers = json_decode(file_get_contents('./whois-list.json'), true);

function LookupDomain($domain){
	global $whoisservers;
	$whoisserver = "";

	$dotpos=strpos($domain,".");
	$domtld=substr($domain,$dotpos+1);

	$whoisserver = $whoisservers[$domtld];

	if(!$whoisserver) {
		return "Error: 没有找到适合您（ <b>$domain</b> ）这个域名的whois服务器! 也可能是该域名的服务商并没有公开whois查询的服务器！";
	}
	$result = QueryWhoisServer($whoisserver, $domain);
	if(!$result) {
		return "Error: 服务器没有返回任何结果 $domain !";
	}

	preg_match("/Whois Server: (.*)/", $result, $matches);
	$secondary = $matches[1];
	if($secondary) {
		$result = QueryWhoisServer($secondary, $domain);
	}
		return  $result;
}

function QueryWhoisServer($whoisserver, $domain) {
	$port = 43;
	$timeout = 10;
	$fp = @fsockopen($whoisserver, $port, $errno, $errstr, $timeout) or die("Socket Error " . $errno . " - " . $errstr);
	fputs($fp, $domain . "\r\n");
	$out = "";
	while(!feof($fp)){
		$out .= fgets($fp);
	}
	fclose($fp);
	return $out;
}
?>
<html>
<head>
	<title>WHOIS Search</title>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	<meta name="keywords" content="fuckyou">
	<link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css">
</head>

<body style="padding: 20px;">
	<div class="container">
		<div class="jumbotron vertical-center">
			<div class="container">
				<h1>Whois 查询
					<small>Fucker's Whois</small>
				</h1><br />
				<p>dalao 来输个米</p>
				<form id="tform" class="form-horizontal" role="form" action="<?php $_SERVER['PHP_SELF'];?>" method="GET">
					<div class="form-group">
						<div class="input-group input-group-lg">
							<span class="input-group-addon">></span>
							<input type="text" id="domain" name="domain" class="form-control search-query" placeholder="Domain name" required>
								<span class="input-group-btn">
									<input class="btn btn-primary" type="submit" value="我要查询">
								</span>
						</div>
					</div>
				</form>
			</div>
		</div> 
	
<?php
if($domain) {
	if(preg_match("/^([-a-z0-9]{1,100})\.([a-z\.]{1,8})$/i", $domain)) {
		$result = LookupDomain($domain);
		echo "<pre>\n" . $result . "\n</pre>\n";
		// die("查询域名WHOIS格式, 比如. <i>cat.net</i>!");
	} else {
		$domain = IDN::decodeIDN($domain);
		$result = LookupDomain($domain);
		echo "<pre>\n" . $result . "\n</pre>\n";
	} 
}
?>

</body>
</html>
<?php
class IDN {
    // adapt bias for punycode algorithm
    private static function punyAdapt(
        $delta,
        $numpoints,
        $firsttime
    ) {
        $delta = $firsttime ? $delta / 700 : $delta / 2; 
        $delta += $delta / $numpoints;
        for ($k = 0; $delta > 455; $k += 36)
            $delta = intval($delta / 35);
        return $k + (36 * $delta) / ($delta + 38);
    }

    // translate character to punycode number
    private static function decodeDigit($cp) {
        $cp = strtolower($cp);
        if ($cp >= 'a' && $cp <= 'z')
            return ord($cp) - ord('a');
        elseif ($cp >= '0' && $cp <= '9')
            return ord($cp) - ord('0')+26;
    }

    // make utf8 string from unicode codepoint number
    private static function utf8($cp) {
        if ($cp < 128) return chr($cp);
        if ($cp < 2048) 
            return chr(192+($cp >> 6)).chr(128+($cp & 63));
        if ($cp < 65536) return 
            chr(224+($cp >> 12)).
            chr(128+(($cp >> 6) & 63)).
            chr(128+($cp & 63));
        if ($cp < 2097152) return 
            chr(240+($cp >> 18)).
            chr(128+(($cp >> 12) & 63)).
            chr(128+(($cp >> 6) & 63)).
            chr(128+($cp & 63));
        // it should never get here 
    }

    // main decoding function
    private static function decodePart($input) {
        if (substr($input,0,4) != "xn--") // prefix check...
            return $input;
        $input = substr($input,4); // discard prefix
        $a = explode("-",$input);
        if (count($a) > 1) {
            $input = str_split(array_pop($a));
            $output = str_split(implode("-",$a));
        } else {
            $output = array();
            $input = str_split($input);
        }
        $n = 128; $i = 0; $bias = 72; // init punycode vars
        while (!empty($input)) {
            $oldi = $i;
            $w = 1;
            for ($k = 36;;$k += 36) {
                $digit = IDN::decodeDigit(array_shift($input));
                $i += $digit * $w;
                if ($k <= $bias) $t = 1;
                elseif ($k >= $bias + 26) $t = 26;
                else $t = $k - $bias;
                if ($digit < $t) break;
                $w *= intval(36 - $t);
            }
            $bias = IDN::punyAdapt(
                $i-$oldi,
                count($output)+1,
                $oldi == 0
            );
            $n += intval($i / (count($output) + 1));
            $i %= count($output) + 1;
            array_splice($output,$i,0,array(IDN::utf8($n)));
            $i++;
        }
        return implode("",$output);
    }

    public static function decodeIDN($name) {
        // split it, parse it and put it back together
        return 
            implode(
                ".",
                array_map("IDN::decodePart",explode(".",$name))
            );
    }

}