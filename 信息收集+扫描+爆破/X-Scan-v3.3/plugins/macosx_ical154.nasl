#TRUSTED 86d226d8cb2f2b21aedff28fa577942f4120b72f146bd41aa1492454908e932938e62c44f51a2c954ea89100ea1c6fc58f178e5bb1c4d78ef900a9a3955e2d936d06273687faa6693b13905b937a2eb62467368722f71030030829b93f4bab3d405deb718abc64dba48555c988cd9c030d612da856d9da72ec27addfb7cc566700f6f876a2441fad64a3f1c5617b834d0634f0dd1a24ce2de3c737a6825fa3c5253d864d93fb19464d37800c07aa4164029cc8a134c32b556f03b1e470aa2e5cdd8f6ee3a1d5f450c246fa172998f91105024513c04ae0f5e51c7b6b91bb091091c1002c5dd9b3d19b41a6b69736523e35fbe53a1fa437534808ed9a3523279e31bd7cd9ccb0752eba8f67d8aef96262fe8a843b1b9e347a6e5afcafda2aa665df5dad3c2ff85863ad3f076ed705f21d0f5fa4fb4acd0a1b4de5245bbd9f3a78c11804e32c053eac472030a2ed1e508ae0b80b831bf39b23a8e0b02a71e8608d35b28b9f0560cebc96bf14e9c98547f84c5425e6520ed5d1c095afec64150fcad9136b04916da5f9c63f71765f5341e2afb0dc46ecc04d8d8740f170158f65f02646270d56b10786e6c64c0db6cd5787b0ca8af0d1aa392e2dffb70d2236b83a2aee98006ae31985d52d58a3a0a0d0b597bef791829b62a1f6389815c46ede9d1059a36ad743194175382ade97c7488cad16746d5ea6acf011fb5831685a0eda
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15786);
 script_version ("1.5");

 script_cve_id("CVE-2004-1021");
 script_bugtraq_id(11728);
 script_xref(name:"OSVDB", value:"12094");
 script_xref(name:"Secunia", value:"13277");
 
 script_name(english:"iCal < 1.5.4");
 script_summary(english:"Check for iCal 1.5.4");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote host is missing a Mac OS X update that fixes a security\n",
     "issue."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running a version of iCal which is older than\n",
     "version 1.5.4.  Such versions have an arbitrary command execution\n",
     "vulnerability.  A remote attacker could exploit this by tricking\n",
     "a user into opening or importing a new iCal calendar."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?bd087f47 (Apple advisory)"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to iCal 1.5.4 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P"
 );
 script_set_attribute( 
  attribute:"plugin_publication_date",  
  value:"2004/11/22"
 ); 
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");
packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


cmd = GetBundleVersionCmd(file:"iCal.app", path:"/Applications");
uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  if ( islocalhost() )
   buf = pread(cmd:"bash", argv:make_list("bash", "-c", cmd));
  else 
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:cmd);
   ssh_close_connection();
  }
 if ( buf && ereg(pattern:"^(1\.[0-4]\.|1\.5\.[0-3]([^0-9]|$))", string:buf) ) security_warning (0);
}
