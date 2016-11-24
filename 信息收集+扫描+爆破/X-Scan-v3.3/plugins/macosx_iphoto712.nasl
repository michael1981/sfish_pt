#TRUSTED 9de15a325419fdaff094f7f2afe79a791f75936cad684ac869fdb0203e66bf658f3680c95f6069773ae474e1e295e43cedaa216903928a89afa32c845847a8428afbb2026e8c07b483f629dc7b464bf8b8c73c997974d0d71390ddcdbe344f47c2e45eaa55e51176738a293c29051dcd0be4892b7af3e1b56b5a05f021a4da0626b8c29b9311b96ee93a73f3e64928f7ae7b7bb4fab7f74042cf08c1a6cb17b8b24789fc04aa21b8e386c171edaae855dcb170f33355b9f55140930b56afd66b5c64a23f346b19c4351a44468bd2e34cfd81cb4987fb21ba45f3f6691a7a235779d9c2245b049e03d8815a57abd9e213fcac36f8c566f5cee45f1fb4c75464b69133c3e136face4e0ad1a78e3825e69cd432a743458cab7f25f5c261e4ce38f3c17eea8254c00f51934f196ef801b2c7c2aabd4b8e4071ccbd09dd31de9cd4b4bb87f2432337f30ec74c9237dc1f4551a5c4e43348422c10f8073a62993b8391712eb9ae1da79cd138b9704f00895cb67b9d05aa486b540fc5ed347fc421319a2aa66c731f3345fd5bab9f6f2a03dfe48f7f132da5b21d55116ed12fdd9a01c46ba8e06991ae3712c98da930fb4a142840743eb87b8dea3484b4550f78b1ace25e331f5d70e1abd655d333080285579cd3bd2ccb25b477880ba028ff698fe09279d0483ecbc358d96611da04e0185231d6740c6e5cfa64a044ef1c23c0b096b1
#
# (C) Tenable Network Security, Inc.
#
#


if (!defined_func("bn_random")) exit(0);



include("compat.inc");

if (description)
{
  script_id(30201);
  script_version ("1.1");

  script_cve_id("CVE-2008-0043");
  script_bugtraq_id(27636);

  script_name(english:"iPhoto < 7.1.2 Format String Vulnerability");
  script_summary(english:"Checks version of iPhoto");

 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by a
format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of iPhoto 7.1 older than version
7.1.2.  Such versions are reportedly affected by a format string
vulnerability.  If an attacker can trick a user on the affected host
into subscribing to a specially-crafted photocast, he may be able to
leverage these issues to execute arbitrary code on the affected host
subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307398" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Feb/msg00000.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.apple.com/support/downloads/iphoto712.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to iPhoto 7.1.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2008 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}



include("macosx_func.inc");
include("ssh_func.inc");


uname = get_kb_item("Host/uname");
if (!uname) exit(0);

if (egrep(pattern:"Darwin.*", string:uname))
{
  cmd = GetBundleVersionCmd(file:"iPhoto.app", path:"/Applications");
  if (islocalhost())
    version = pread(cmd:"bash", argv:make_list("bash", "-c", cmd));
  else 
  {
    ret = ssh_open_connection();
    if (!ret) exit(0);

    version = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }

  if (version)
  {
    version = chomp(version);
    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (
      ver[0] == 7 && 
      (
        ver[1] == 0 ||
        (ver[1] == 1 && ver[2] < 2)
      )
    )
    {
        report = string(
          "\n",
          "The remote version of iPhoto is ", version, ".\n"
        );
        security_warning(port:0, extra:report);
    }
  }  
}
