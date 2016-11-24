#TRUSTED 1ad91b427843744513f77ce921cac753200eb9e132b80aa0328fd26b23f574764db9bfb27eb76ec494e2bc17b1988dca9ef5597e0ede0baeb8ff3a85bcd5c64a065f7d509aec2dd8f17b49eb7a641f7cd091083ba4bb2b797f3f00cbd619d8037332a355db1b559a3a288b5b5b2d7a352c9ed3626ec1fe98c2e7aa7877f5da9644a1832ca7d20ed33c5b89600b1bbf22d19063b7ccc742457c11fe99c11e2584254809acf89b30039659a60d1fd071b754d95a0f5e1a6fdb5505659e5f3eb642513ebd4c6039e6129a1e097108641ccaddd01ebf8eec9048513575548542f928d95169abc58beab3517640aa2e2498ce41bb5d3134d30a2c06e8bab90a14df3a48ae5e1f4bc42d0245318ac82bdc055a241650090a649b59edc709d3b5ab55f8ea5f178ee2a22139a2cb727e710f8b59c6bf90a5c4d63520ca5223f1bc8a85f30b457e892bd245120d9904a5c502e5ef65e08b7d39f14e7f1c5c3a087544eda02a6bddc1e651763d9689d4693b401c9f60ae250242ecaff8248f65d225ccba6df651877b497585fc82b4e0f9744fab16ba504a4053a197dbf312f2fa8866297e43a7167a200d4a4debfbced30b024794c8cabb0933f44bcee7ab27014fa3d3bd092e08c7945341b45e11fb82ba22b16dfbb0a6833f206ab042a22dca25a2d01d0086fdb1d217d4f67bf139754b899384836167df36a911836ff0aac01d163ce1
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if (description)
{
 script_id(34291);
 script_version("1.3");

 script_cve_id(
  "CVE-2008-1185",
  "CVE-2008-1186",
  "CVE-2008-1187",
  "CVE-2008-1188",
  "CVE-2008-1189",
  "CVE-2008-1190",
  "CVE-2008-1191",
  "CVE-2008-1192",
  "CVE-2008-1193",
  "CVE-2008-1194",
  "CVE-2008-1195",
  "CVE-2008-1196",
  "CVE-2008-3103",
  "CVE-2008-3104",
  "CVE-2008-3105",
  "CVE-2008-3106",
  "CVE-2008-3107",
  "CVE-2008-3108",
  "CVE-2008-3109",
  "CVE-2008-3110",
  "CVE-2008-3111",
  "CVE-2008-3112",
  "CVE-2008-3113",
  "CVE-2008-3114",
  "CVE-2008-3115",
  "CVE-2008-3637",
  "CVE-2008-3638"
 );
 script_bugtraq_id(28125, 30144, 30146, 31379, 31380);
 script_xref(name:"OSVDB", value:"46955");
 script_xref(name:"OSVDB", value:"46956");
 script_xref(name:"OSVDB", value:"46957");
 script_xref(name:"OSVDB", value:"46958");
 script_xref(name:"OSVDB", value:"46959");
 script_xref(name:"OSVDB", value:"46960");
 script_xref(name:"OSVDB", value:"46961");
 script_xref(name:"OSVDB", value:"46962");
 script_xref(name:"OSVDB", value:"46963");
 script_xref(name:"OSVDB", value:"46964");
 script_xref(name:"OSVDB", value:"46965");
 script_xref(name:"OSVDB", value:"46966");
 script_xref(name:"OSVDB", value:"46967");
 script_xref(name:"OSVDB", value:"49091");
 script_xref(name:"OSVDB", value:"49092");

 name["english"] = "Mac OS X : Java for Mac OS X 10.4 Release 7";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.4 host is running a version of Java for Mac OS
X that is older than release 7. 

The remote version of this software contains several security
vulnerabilities which may allow a rogue java applet to execute
arbitrary code on the remote host. 

To exploit these flaws, an attacker would need to lure an attacker
into executing a rogue Java applet." );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3178" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Sep/msg00008.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.4 release 7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Check for Java Release 7 on Mac OS X 10.4";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");

function exec(cmd)
{
 local_var ret, buf;

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
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# Mac OS X 10.4.11 only
if ( egrep(pattern:"Darwin.* 8\.11\.", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 # Fixed in version 11.8.0
 if ( int(array[0]) < 11 ||
     (int(array[0]) == 11 && int(array[1]) < 8 ) )
 {
   security_hole(0);
 }
}
