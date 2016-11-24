#TRUSTED 05b4c1666fac6ee239f05b57141d7786244ff28202537a5062e2e7a170007d4d08f346c12658668abc3f82ca8490c2d22c60684b7ac59a44fde328cc881eb9251035bd55f97de0edf061068daa698b8bee7bc1ed19683bb896e95d4e45abd134ae8a0ee1e0fa84455bae82c995489e9b7e2a9c2aa65944c4350b8efe909796a8283909ee54a92f0257910a696d09a737ef9b9778e7a87d833a0597b2c10c19d9bd24b26c5e274d5d90a5b0d113df3e492f782683f380d24a3c4285a8efca3b5f5d5cfb68a64afef5c143cead4839ab5e1b707c837170184abf81c9735a6a1190ca5ddec4b75c8f616831c247aed3c617ef875fa3144e1dec2cd1da7744ff369c2a9b8ececb3380923ada5a24efee6ebe92f3bffd8b37249d7b9aaca1bb8ebc820311d462ae87dcaa706c1eeb0fc4575b0fe6d52dbd24b721647f351d128b107fdff8f365eeb731d9bebb9de0e627e3f33173f44ae2e52360112a7d5c76500fa40cde21d2ad2e2a087a7edd2b4c795719733e1106411a5522c79a08322988dc36d32d2c6ea9edc268dc38d2f3fd0e12546ff65fcf56f396dd3cf595a1ae54b270f366be4e7b38d77de7538431e39b09f83f585237ea0efe6d0d70edd7f4f506405c26a970c61492bce68a9d7d0126830fbae49c7b80b3b41828b94c70da197920e4d748a2628463fc1fe305952a4e522e390837a1b0d96775b287ed1b6212fc27
#
#  (C) Tenable Network Security
#




include("compat.inc");

if (description)
{
  script_id(25997);
  script_version("1.0");

  script_name(english:"iTunes Version Detection (Mac OS X)");
  script_summary(english:"Check the version of iTunes"); 
 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a copy of iTunes installed." );
 script_set_attribute(attribute:"description", value:
"The remote host is running iTunes, a popular jukebox program." );
 script_set_attribute(attribute:"solution", value:
"Delete this software if you do not use it");
 script_set_attribute(attribute:"risk_factor", value:
"None" );
 
  script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2007 Tenable Network Security");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");
  exit(0);
}

include("ssh_func.inc");
include("macosx_func.inc");


cmd = GetBundleVersionCmd(file:"iTunes.app", path:"/Applications");
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
  vers = split(chomp(buf), sep:'.', keep:FALSE);
  set_kb_item(name:"MacOSX/iTunes/Version", value:string(int(vers[0]), ".", int(vers[1]), ".", int(vers[2])));
  security_note(port:0, extra:'iTunes ' + string(int(vers[0]), ".", int(vers[1]), ".", int(vers[2])) + ' is installed on the remote host');
 }
}

