#TRUSTED 239b4f66c7b74b1aaadd3fa3362a8236696c54fe3b09c822a511ad1aeda8f4042ec3ac9a41fe12d6dcb30f2e1a837c67e55b488ecf8f4f164724f676999dc2833de63a819c67cdbc5775c7fbebc53d0184c631acad87522b99ef7cfff845fadd0ee3c7cbc77dfa4d69e07cfd3749ca8bee5e522b1bae6f6fe8169da44c8a147f9b10d97708cb74c34f8690804d647244b2a17752805cc08a36fe79fecb0b05e8435d667236876cf40954b3ae75a07ad9aeb71e909b71b0a992418afe8967dc0081ad9b1eb848a33da2c7a19cd8474412d6071863843313873af6b70b135570eaa81b75ead49cff379a8a860ebd5af8661f02f066732827c3b140e48fa965709c4a5bbc1c4b9ad11ffcd751c1583137c45727d3ed8b87feaf258ec736d349d9b1f8ae49f86f118b4141f08329809f0af0c37968e9088e85971d8b8404d0005031b36e18e9a8f405cfdab6f84434f6830da1c5d50b2b0c2c0471fc07e17b166f52fd9d3800d8c290d3f484c30f13eabd966392e5f92149d0df4f84551e4beb53ab156d9121253a5db60a7fa165e1fb8b9fecef1b3470b943703f4a128fb89ad04f6888818a1cf6412bf84ef1112a96f5f54ba88cce633ce31a8deb5451bb65ce34ded4474829d136a0a8b8d10a489f8e992cc9f0d4b96166cf4925318458b21a1bcb3aa2f2f577a8e32ce477763dd49049c7f5926e77b164b20cc29419b7b089e8
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24812);
 script_version ("1.6");

 script_cve_id("CVE-2007-0051");
 script_bugtraq_id(21871);
 script_xref(name:"OSVDB", value:"31165");

 script_name(english:"iPhoto < 6.0.6");
 script_summary(english:"Check for iPhoto 6.0.6");

 script_set_attribute(attribute:"synopsis", value:
"The remote system is missing a security update" );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of iPhoto 6 that is older than
version 6.0.6. 

Such versions contain a security vulnerability that may allow an
attacker to execute arbitrary code on this host. 

To exploit this flaw, an attacker would need to lure a user on the
remote host into subscribing to a malicious photocast album" );
 script_set_attribute(attribute:"solution", value:
"http://docs.info.apple.com/article.html?artnum=305215" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305215" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


cmd = GetBundleVersionCmd(file:"iPhoto.app", path:"/Applications");
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

 if ( buf )
 {
  vers = split(buf, sep:'.', keep:FALSE);
  if ( int(vers[0]) == 6 && int(vers[1]) == 0 && int(vers[2]) < 6  ) security_warning(0);
 }  
}
