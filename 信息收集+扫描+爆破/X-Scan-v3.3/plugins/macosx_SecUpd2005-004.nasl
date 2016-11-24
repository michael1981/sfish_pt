#TRUSTED 19ff497f02bbadc7d1fffcd75b8df2d9acd2d6e61de0b323067807b1b432668d842e6e5c649662e614ed0241b6eb8361b80f864c22e636e25300da6a882e9131ad9eef8ee0f38207c14f9c323c0984f7dc686b1ac2ae5f250156e985078429e50c5d028e409ab855e937e2e52fa7db86b25c2c4528adbda33a3477a94626b48d1577e601c04d1e6c98bcf3fb8636c353c1986f7f7559813b2bfbf553fce2c9e91b941c2bfb1c005dd59ab5c1e11756a41ae22c6398ab3fa398006ac509ced6b06a29435cfa6ae09bbd58cc26360802596797f62b33daf5886ac469772274f0df983a440a7f89b1770cc61b29bf5ee4b1cc28782df5c61012108acee90f424a1544f5ebdb58769d2af81801aca7986b3b25024df361ccd8924e69625fdb4e6739b0b7043374d9ef2f893abebab9602d7a9dac9730d5aae4144936b966f0666c35f2f0f426c8d0e591bdd33addf3c7ecd034840aee608c9dc9236b40d032f0a69903840be81b5562705ef2be1423b68d99f58b6d7d893d2733f71ff425bbc03bd96b6d140fc088ad571752f67572c0f44b79cfdb5a18d13ac37842c70cea712bfe0b16449e21bc662bc1be3238c357d7d9eff60ee21c26ce3f36c67265cd2a4baec970f3945efcd58b58eec890ca98bb8193365d705d46782faa4409b5c3c9b6fec2a4840b22605ec8c4542869a9346e255734ec7e97292454d7f616618d7b71c3
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(18099);
 script_version ("1.9");

 script_cve_id("CVE-2005-0193");
 script_bugtraq_id (12334);
 script_xref(name:"OSVDB", value:"13158");

 script_name(english:"Mac OS X Security Update 2005-004");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote operating system is missing a security update." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Security Update 2005-004.  This security
update contains security fixes for the following application :

- iSync (local privilege escalation)" );
 script_set_attribute(attribute:"solution", value:
"http://docs.info.apple.com/article.html?artnum=301326" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

 summary["english"] = "Check for Security Update 2005-004";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
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
# MacOS X 10.2.8, 10.3.9 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[789]\.)", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"SymbianConduit.bundle", path:"/System/Library/SyncServices", label:"SourceVersion");
 buf = exec(cmd:cmd);
 if ( int(buf) > 0 && int(buf) < 840200 ) security_hole(0);
}
 
