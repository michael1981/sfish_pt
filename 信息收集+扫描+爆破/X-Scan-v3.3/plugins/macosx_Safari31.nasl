#TRUSTED 3a1a005d26bfa758aa6dff90a3ed3543c1c23171a53e14e132419d1c7860d478e5baf41c539a06f31b711db1e4238c1163553cdd7a4a63f3c458417218cbe769b6f3c927e8d54ab9e80f4cb3340484ae58d96db4de898db2198302d73c500d27940410b54b570a29cf0898b4caa2f9a5250391de95fd64392c2e4fc6afe71f5b07ee493daaec60c7a9a6c9f6e9b99fa8bc07e096504475a1445ea41f9076506fd4dbb0fa1e4191e3bb01710a864f7b3b88ff67cc285e2e0fb5545f63b1246125576fd794cd418e373160b6da72957a459e85ee6984b1d422de26a7d55e7adf9fb4559a35f62f26f3e03bf16b69cd5f3b876aa3f1af7c147b5540522e2024509558105f2b8338ceabaf50ac0d642e660223d92fcf84c035d005050650d4746d065c4da5f1f5e834075dd1e21d35625eded968746d440437126b2c46bfde2c9e6dce757816c3412f97446688c2e257f1a3551ba3e65b8808f0498e8d54ba2d9c041d4788635a96c63b671e0ba85d4a23bee68d5cc37b0d16d86a0669286ce5c1bd23d5a6e4d8897f48779361cd4f5e12ae5719c29ec591eace62038e1bc186d29706f997ce75a848f9c5da4f767658664fef5c3526aaff3d56f703984a5c96d6d4dfe62f62cd4a7865db4227762bcf51542db0f9244346fd3ad5376a237618c737e291686816a766f7a67edc0e2cfdc5cc048b0319e2aeacf96df3ba0fef603805
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3004) exit(1);

include("compat.inc");

if(description)
{
 script_id(31604);
 script_version("1.9");

 script_cve_id(
  "CVE-2008-1002", 
  "CVE-2008-1003", 
  "CVE-2008-1004", 
  "CVE-2008-1005", 
  "CVE-2008-1006", 
  "CVE-2008-1007", 
  "CVE-2008-1008", 
  "CVE-2008-1009", 
  "CVE-2008-1010", 
  "CVE-2008-1011"
 );
 script_bugtraq_id(
  28326,
  28328,
  28330,
  28332,
  28335,
  28336,
  28337,
  28338,
  28342,
  28347,
  28356
 );
 script_xref(name:"OSVDB", value:"43359");
 script_xref(name:"OSVDB", value:"43360");
 script_xref(name:"OSVDB", value:"43361");
 script_xref(name:"OSVDB", value:"43362");
 script_xref(name:"OSVDB", value:"43363");
 script_xref(name:"OSVDB", value:"43364");
 script_xref(name:"OSVDB", value:"43365");
 script_xref(name:"OSVDB", value:"43366");
 script_xref(name:"OSVDB", value:"43367");
 script_xref(name:"OSVDB", value:"43368");

 script_name(english:"Mac OS X : Safari < 3.1");
 script_summary(english:"Check the Safari SourceVersion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Safari installed on the remote host is older than
version 3.1. 

The remote version of this software contains several security
vulnerabilities that may allow an attacker to execute arbitrary code
or launch a cross-site scripting attack on the remote host. 

To exploit these flaws, an attacker would need to lure a victim into
visiting a rogue web site or opening a malicious HTML file." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307563" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Safari 3.1." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/18");
 script_end_attributes();

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
 local_var buf, ret, soc;

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
# Mac OS X 10.4, 10.5.2
if ( egrep(pattern:"Darwin.* (8\.|9\.[012]\.)", string:uname) )
{
 cmd = 'cat /Applications/Safari.app/Contents/Info.plist|grep -A 1 CFBundleGetInfoString| tail -n 1 | sed \'s/<string>\\(.*\\)<\\/string>.*/\\1/g\'|awk \'{print $1}\'|sed \'s/,//g\'';
 buf = exec(cmd:cmd);
 if ( buf !~ "^[0-3]\." ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 if ( int(array[0]) < 3 ||
      (int(array[0]) == 3 && int(array[1]) < 1) ) security_hole(0);
}
