#TRUSTED 5bf259030fa8e13e69f51b0ca0fb06cb08b31071160af38458649a7232da8b58e46c94d1542fe4be9b56251c19d21874819a01ad2630c139da202cc1d49d12a1e08c710e6c12646ff99d2d97991854bce58b08fb8cdf69f38d13e96340be9b4651d37a824179fb895f429cc9f229e625a5ab07a8ba30ec45c221ecea564aa89a3942cf2aa5ebc1c8645d2d57d46f05037092ed00b9d63cf00870d19f6fd681927c5d63de8ea529222de51b1946fd3677355da17c2ade866255362acb3fdaee382e6c352f3d6490f465fa14f434c89b9820993f530b703412854a1a35795d8d385dd3080dc2c86dfd0b82e217d20206aecad9adafe87c837f0790f036f7e1e0c7131e702acdd7d0c1a9495b49bc517b5b59608451522d481a322816e706e1780e39b1af86257865c58d4395e324ac28e3d889531931c12b11c2e8648b33b4cad21681344a2a6c52c0b58776d52cb441987f73ecef0280afbe247bceec8ef84684fcbefbf68847dd218e309df54c8ff88fd09809d159d8291f22645a46cb67246305858c53f30813f8b96a82dbe26f9c9af83c800f059f1a0d1699bc3d3e2b0713eb804c82e4d26e9a5cb234b704dd3707076a99762d3381cd673a4f2052f7bbf03a8b7d17490ff88362ce01262dfd1f401c14a4a82aa9e725f965e10f02b007bd6ed6d49502ba7977b2396b6a46e9e02849f79d7a7fed5bc9e4cac9b018a17314
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);



include("compat.inc");

if (description)
{
  script_id(31992);
  script_version ("1.4");

  script_cve_id("CVE-2008-1025", "CVE-2008-1026");
  script_bugtraq_id(28814, 28815);
  script_xref(name:"OSVDB", value:"43980");
  script_xref(name:"OSVDB", value:"44468");
  script_xref(name:"Secunia", value:"29846");

  script_name(english:"Mac OS X : Safari < 3.1.1");
  script_summary(english:"Check the Safari SourceVersion");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Safari installed on the remote host reportedly is
affected by several issues :

  - A cross-site scripting vulnerability exists in WebKit's
    handling of URLs that contain a colon character in
    the host name (CVE-2008-1025).

  - A heap buffer overflow exists in WebKit's handling of
    JavaScript regular expressions (CVE-2008-1026)." );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1467" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Apr/msg00001.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Safari 3.1.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2008 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

  exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


function exec(cmd)
{
 local_var ret, soc, buf;

 if ( islocalhost() )
  buf = pread(cmd:"bash", argv:make_list("bash", "-c", cmd));
 else
 {
  ret = ssh_open_connection();
  if ( ! ret ) exit(0);
  buf = ssh_cmd(cmd:cmd);
  ssh_close_connection();
 }

 if ( buf !~ "^[0-9]" ) exit(0);

 buf = chomp(buf);
 return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0);

uname = get_kb_item("Host/uname");
if (!uname) exit(0);

# Mac OS X 10.4, 10.5.2
if ( egrep(pattern:"Darwin.* (8\.|9\.[012]\.)", string:uname) )
{
 cmd = 'cat /Applications/Safari.app/Contents/Info.plist|grep -A 1 CFBundleGetInfoString| tail -n 1 | sed \'s/<string>\\(.*\\)<\\/string>.*/\\1/g\'|awk \'{print $1}\'|sed \'s/,//g\'';
 buf = exec(cmd:cmd);
 if ( buf !~ "^[0-3]\." ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 if ( int(array[0]) < 3 ||
      (int(array[0]) == 3 && int(array[1]) < 1) ||
      (int(array[0]) == 3 && int(array[1]) == 1 && int(array[2]) < 1) ) security_hole(0);
}

