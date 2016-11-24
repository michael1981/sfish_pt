#TRUSTED 7764edca5f558e562e96fe7ec1382464afa01a09c8df510939f2f1975a1702d8a3afdb5fc52a353ae73b0c56ad9f85ec41893138165123ef5a1a734cae8ce75fee48c1b99fa20f04332eb20e28d76da3191a23a35c9e2cb6ea7abf7f601713e899aaa56574eaf4b99ce46d427126a3fff5923f84a198a0550180630f8d4d47fac73706282a447bc1cdbe3e06a936a5a827f63b8ba952084838b5f066b914b6543a0c3cef341a6fbb9953411c5907561695285b063818278c1b56afc5e05640baf09938d175afd85b6ea8b556edceb67d421a52cd0490874f800ee3d4d173f7b2195fcbc3c021fc1459306cb4382df8848621f87436c1b71310acac6330695251a29f46bf8bee07ff9cc56a0c06805411247bffae6295463f167f59a552ed19b30a37d20a432243c1ab4a05fe77042baf06232c148a27ae3f703f4a105e5776321e712fa3274ea89ed930e44e8aadc934c7db88fb830f06f145553e0f3292f6205c4813473500e7aa51cd54fc61ad6820527bce8de1eb23b66d0a559168d8144d935c49811a5b282bd8bde4bedb3aa390ff47957e325756f8d986acd7ae7a1e5361dd4243a23b4830c71f77ffe4d46c737290cb2c10d296bcb628ab84173f1f13af6e753dd9a4db34f083f4b3c8b9e0bf4a963c5e85133fd91460ae9e4393cd89fb0456812235f5c5cdb7cf26cab7a4c7c1ce1e5a8fa1358a67ee69174d3a2ad9
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15573);
 script_version ("1.10");

 script_cve_id("CVE-2004-0988");
 script_bugtraq_id(11553);
 script_xref(name:"OSVDB", value:"11202");
 script_xref(name:"Secunia", value:"13005");

 script_name(english:"Quicktime < 6.5.2");
 script_summary(english:"Check for Quicktime 6.5.2");
 
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
     "The remote Mac OS X host is running a version of Quicktime which is\n",
     "older than Quicktime 6.5.2.\n\n",
     "There is an integer overflow vulnerability in the remote version of\n",
     "this software which may allow an attacker to execute arbitrary code\n",
     "on the remote host.  A remote attacker could exploit this flaw by\n",
     "tricking a user into opening a maliciously crafted media file."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-10/0297.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"http://support.apple.com/kb/HT1646"
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P"
 );
 script_set_attribute( 
  attribute:"plugin_publication_date",  
  value:"2004/10/27"
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

cmd = GetBundleVersionCmd(file:"QuickTimeMPEG.component", path:"/System/Library/Quicktime");

if ( islocalhost() )
 buf = pread(cmd:"bash", argv:make_list("bash", "-c", cmd));
else
{
 ret = ssh_open_connection();
 if ( !ret ) exit(0);
 buf = ssh_cmd(cmd:cmd);
 ssh_close_connection();
}

if ( buf !~ "^[0-9]" ) exit(0);

buf = chomp(buf);

set_kb_item(name:"MacOSX/QuickTime/Version", value:buf);

version = split(buf, sep:'.', keep:FALSE);

if ( int(version[0]) < 6 ||
    ( int(version[0]) == 6 && int(version[1]) < 5 ) ||
    ( int(version[0]) == 6 && int(version[1]) == 5 && int(version[2]) < 2 ) ) security_warning ( 0 );
