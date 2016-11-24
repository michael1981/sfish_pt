#TRUSTED 4a6ae1f231ccc02b824568985c3a6b0b5d3231f54f8a570d19b1e4ee0bb87fafcbc4d86441994cdfa6718d926c6f4508b21e6b163fce574025eb846913c966bacba2eba2d422bd32d714d7188507f1947ac65a1b76ddc202245ed60d4198660c570ceac7ed2d2c6483a3a59e7e2ec3aa230b3d5a4f30c0c94d33644d7df1c36ac5dc5b025dd41733aabd17876b908ffc74490ababe298df9ab6adedeaa1453ef1cf10d0d0a58d02af66a5aa2307ed7b2a99faa1317bcb27aa0ea7dea1c60d549b6b53fb24f7e3170d0d9d2d09197d121dd9a91dc2f074bf31e7f069a91cb7d96d12849e5334d343ad47e99ad363bbeb01555314b2b1db037a5121f2cce448b51a7de681a0ae26e78c3c70d335f4c4a3db7c5cab05f6b0ca00d5dbc2b7e739393b7cba19f02ab32c73f28358e9ea8d9be155072cc838931d8b55e8a17aa9c0de35b2110d13730b27b72c55cb6c03f0f8f2b4b86c4769be7b9421003b070bcd7cb61f7f4b89febea6f2acc3993faf841032445a007c0831d0cc7752dd7e030f4d9d040fd888f76827a81595a12ce7c9f151f52bae0c43a484227a66b8ba94d04d55a20924378ce0c11a31a7a777907f84584b6bcb1cedd8da4556438ad3b6fc46660adb3ab194a0c8c56ba5a87619268ddcbc89461079a31dc0403f6164ae23ca8f8c7920461db32e1ff1cbfc60eb9d02f372c97b65fe065b92aed355d4f2a68a3
#
# (C) Tenable Network Security, Inc.
#


if ( ! defined_func("pread") || ! defined_func("fread") ||
     ! defined_func("get_preference") ) exit(0);
if ( ! find_in_path("amap") ) exit(0);


include("compat.inc");


if(description)
{
 script_id(14663);
 script_version ("1.22");

 script_name(english: "amap (NASL wrapper)");
 script_summary(english: "Performs portscan / RPC scan / application recognition"); 

 script_set_attribute(
  attribute:"synopsis",
  value:"This plugin performs application protocol detection."
 );
 script_set_attribute(
  attribute:"description",
  value:string(
   "This plugin runs amap to find open ports and identify applications on\n",
   "the remote host.\n",
   "\n",
   "See the section 'plugins options' to configure it."
  )
 );
 script_set_attribute(
  attribute:"see_also",
  value:"http://www.thc.org/thc-amap/"
 );
 script_set_attribute(
  attribute:"risk_factor",
  value:"None"
 );
 script_set_attribute(
  attribute:"solution",
  value:"n/a"
 );
 script_end_attributes();

 script_category(ACT_SCANNER);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english: "Port scanners");

 if (NASL_LEVEL >= 3210)
  script_dependencies("portscanners_stub.nasl", "portscanners_settings.nasl");
 else
  script_dependencies("ping_host.nasl", "portscanners_settings.nasl");

 if (NASL_LEVEL < 2181) exit(0);	# Cannot run

 script_add_preference(name: "File containing machine readable results : ", value: "", type: "file");

 script_add_preference(name:"Mode", type:"radio", value: "Map applications;Just grab banners;Port scan only");
 script_add_preference(name:"Quicker", type:"checkbox", value: "no");
 script_add_preference(name:"UDP scan (disabled in safe_checks)", type:"checkbox", value: "no");
 script_add_preference(name:"SSL (disabled in safe_checks)", type:"checkbox", value: "yes");
 script_add_preference(name:"RPC (disabled in safe_checks)", type:"checkbox", value: "yes");

 script_add_preference(name:"Parallel  tasks", type:"entry", value: "");
 script_add_preference(name:"Connection retries", type:"entry", value: "");
 script_add_preference(name:"Connection timeout", type:"entry", value: "");
 script_add_preference(name:"Read timeout", type:"entry", value: "");

 exit(0);
}

#
function hex2raw(s)
{
 local_var i, j, ret, l;

 s = chomp(s);  # remove trailing blanks, CR, LF...
 l = strlen(s);
 if (l % 2) display("hex2raw: odd string: ", s, "\n");
 for(i=0;i<l;i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
        j = int(s[i]);
  else
        j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
        j += int(s[i+1]);
  else
        j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}

if (NASL_LEVEL < 2181 || ! defined_func("pread") || ! defined_func("get_preference"))
{
  set_kb_item(name: "/tmp/UnableToRun/14663", value: TRUE);
  display("Script #14663 (amap_wrapper) cannot run - upgrade libnasl\n");
  exit(0);
}

function do_exit()
{
  global_var tmpnam;
  if (tmpnam) unlink(tmpnam);
}

ip = get_host_ip();
esc_ip = ""; l = strlen(ip);
for (i = 0; i < l; i ++) 
  if (ip[i] == '.')
    esc_ip = strcat(esc_ip, "\.");
  else
    esc_ip = strcat(esc_ip, ip[i]);

res = script_get_preference_file_content("File containing machine readable results : ");
if (res)
  res = egrep(pattern: "^" + esc_ip + ":[0-9]+:", string: res);
if (! res)
{
  # No result, launch amap
  if (get_kb_item("PortscannersSettings/run_only_if_needed")
      && get_kb_item("Host/full_scan")) exit(0);

tmpdir = get_tmp_dir();
if ( ! tmpdir ) do_exit();
tmpnam = strcat(tmpdir, "amap-", get_host_ip(), "-", rand());

p = script_get_preference("UDP scan (disabled in safe_checks)");
if ("yes" >< p)
 udp_n = 1;
else
 udp_n = 0;

n_ports = 0;

for (udp_flag = 0; udp_flag <= udp_n; udp_flag ++)
{
 i = 0;
 argv[i++] = "amap";
 argv[i++] = "-q";
 argv[i++] = "-U";
 argv[i++] = "-o";
 argv[i++] = tmpnam;
 argv[i++] = "-m";
 if (udp_flag) argv[i++] = "-u";

 p = script_get_preference("Mode");
 if ("Just grab banners" >< p) argv[i++] = '-B';
 else if ("Port scan only" >< p) argv[i++] = '-P';
 else argv[i++] = '-A';

 # As all UDP probes are declared harmful, -u is incompatible with -H
 # Amap exits immediatly with a strange error.
 # I let it run just in case some "harmless" probes are added in a 
 # future version

 if (safe_checks()) argv[i++] = "-H";

 p = script_get_preference("Quicker");
 if ("yes" >< p) argv[i++] = "-1";

 # SSL and RPC probes are "harmful" and will not run if -H is set

 p = script_get_preference("SSL (disabled in safe_checks)");
 if ("no" >< p) argv[i++] = "-S";
 p = script_get_preference("RPC (disabled in safe_checks)");
 if ("no" >< p) argv[i++] = "-R";

 p = script_get_preference("Parallel  tasks"); p = int(p);
 if (p > 0) { argv[i++] = '-c'; argv[i++] = p; }
 p = script_get_preference("Connection retries"); p = int(p);
 if (p > 0) { argv[i++] = '-C'; argv[i++] = p; }
 p = script_get_preference("Connection timeout"); p = int(p);
 if (p > 0) { argv[i++] = '-T'; argv[i++] = p; }
 p = script_get_preference("Read timeout"); p = int(p);
 if (p > 0) { argv[i++] = '-t'; argv[i++] = p; }

 argv[i++] = ip;
 pr = get_preference("port_range");
 if (! pr) pr = "1-65535";
 foreach p (split(pr, sep: ',')) argv[i++] = p;

 res1 = pread(cmd: "amap", argv: argv, cd: 1, nice: 5);
 res += fread(tmpnam);
 }
}

# IP_ADDRESS:PORT:PROTOCOL:PORT_STATUS:SSL:IDENTIFICATION:PRINTABLE_BANNER:FULL_BANNER

foreach line(split(res))
{
  v = eregmatch(string: line, pattern: '^'+esc_ip+':([0-9]+):([^:]*):([a-z]+):([^:]*):([^:]*):([^:]*):(.*)$');
  if (! isnull(v) && v[3] == "open")
  {
   scanner_status(current: ++ n_ports, total: 65535 * 2);
   proto = v[2];
   port = int(v[1]); ps = strcat(proto, ':', port);
   scanner_add_port(proto: proto, port: port);
   # As amap sometimes give several results on a same port, we save 
   # the outputs and remember the last one for every port
   # The arrays use a string index to save memory
   amap_ident[ps] = v[5];
   amap_ssl[ps] = v[4];
   amap_print_banner[ps] = v[6];
   amap_full_banner[ps] = v[7];

  }
}

if (n_ports != 0)
{
 set_kb_item(name: "Host/scanned", value: TRUE);
 set_kb_item(name: 'Host/scanners/amap', value: TRUE);
 if (pr == '1-65535')
   set_kb_item(name: "Host/full_scan", value: TRUE);
}

if (udp_n && n_ports)
  set_kb_item(name: "Host/udp_scanned", value: 1);

scanner_status(current: 65535 * 2, total: 65535 * 2);

function cvtbanner(b)
{
  local_var i, l, x;
  l = strlen(b);

  if (b[0] == '0' && b[1] == 'x')
   return hex2raw(s: substr(b, 2));

  x = "";
  for (i = 0; i < l; i ++)
   if (b[i] != '\\')
    x += b[i];
   else
   {
    i++;
    if (b[i] == 'n') x += '\n';
    else if (b[i] == 'r') x += '\n';
    else if (b[i] == 't') x += '\t';
    else if (b[i] == 'f') x += '\f';
    else if (b[i] == 'v') x += '\v';
    else if (b[i] == '\\') x += '\\';
    else display('cvtbanner: unhandled escape string \\'+b[i]+'\n');
   }
  return x;
}

if (! isnull(amap_ident))
 foreach p (keys(amap_ident))
 {
  v = split(p, sep: ':', keep: 0);
  proto = v[0]; port = int(v[1]);
  if (proto == "tcp")
  {
   soc = open_sock_tcp(port);
   if (soc)
    close(soc);
   else
    security_hole(port: port, data: "Either this port is dynamically allocated
or amap killed this service.
If so, upgrade it!

Risk : None / High\n");
  }
  id = amap_ident[p];
  if (id && id != "unidentified" && id != 'ssl')
  {
   security_note(port: port, proto: proto, data: "Amap has identified this service as " + id);
   set_kb_item(name: "Amap/"+proto+"/"+port+"/Svc", value: id);
  }

  banner = cvtbanner(b: amap_print_banner[p]);
  set_kb_item(name: "Amap/"+proto+"/"+port+"/PrintableBanner", value: banner);

  banner = cvtbanner(b: amap_full_banner[p]);
  set_kb_item(name: "Amap/"+proto+"/"+port+"/FullBanner", value: banner);
 }


do_exit();
