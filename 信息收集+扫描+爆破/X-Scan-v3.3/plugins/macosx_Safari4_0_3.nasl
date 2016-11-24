#TRUSTED 3ca150e66e8c20af457b49b398788b9d9a7cf338fbcdf7d4db8c5567792720852382172be0d9a8007196f630d6f4238378101f3f45709a115cdb0ba95243397de12e3c9499581bc5c92419bf14ed7a6d10fa1694dcf95f614f727a5708e4bc150c58e9cd9a38a63059e35848052cc5e147b6ad745e79d398575dab82ba44c5183cf9b72ad689c3fe025b33f60e56fcea8e5a61dfd60066b1b5e3074b1ddba45136c3139520057c5f865fc0b6816a044a92b30932cbcdf167c19a8613853de795138e4a94a5d8e0be83c31216aeb963f49fffe97bd08db5e89954db92bc02b36e0815164600007c81335384abeb6222db3e4c8a1fefbf1bf1cc743f7a914e461f30980dbcf04c518418fa4744ba93b63cd6fe96363d6027385bd3a9562ee75e09ef820c2ea4bbfc15473674cdc7e3194ee10d141d78de4469e8ca06bb34bd27a2837e2a6567348e63d244442ade5a4fe574ad6c2f7f884c597d16d6f0038b7354fdcf9900ba82945586ebf9ab7fe6ab194d146c55a5464a8dbd5adb2fa32d57cfaf042566ad66ba57064908dcd0313956777270115d3826f54b2ee1b78f387b4046b5eaa4447a0b9188dbd48d7843c2510e56168f5d0a4fcd4209fbad92e02783b0beedce2d75e6c36e5f00360be0ca792ecb2f2e9bb06ab6bb3cedde2bcf7c613d4c4ca4dcd24e535e4e6c2ab6cdeda80391e67c5bbaa17f5d83ea7b25b01872
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(40553);
  script_version("1.2");

  script_cve_id(
    "CVE-2009-2195", 
    "CVE-2009-2196",
    "CVE-2009-2199",
    "CVE-2009-2200"
  );
  script_bugtraq_id(36022, 36023, 36024, 36026);
  script_xref(name:"OSVDB", value:"56986");
  script_xref(name:"OSVDB", value:"56987");
  script_xref(name:"OSVDB", value:"56988");
  script_xref(name:"OSVDB", value:"56989");

  script_name(english:"Mac OS X : Safari < 4.0.3");
  script_summary(english:"Check the Safari SourceVersion");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host contains a web browser that is affected by several\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Safari installed on the remote Mac OS X host is earlier\n",
      "than 4.0.3.  Such versions are potentially affected by several issues :\n",
      "\n",
      "  - A vulnerability in WebKit's parsing of floating point\n",
      "    numbers may allow for remote code execution.\n",
      "    (CVE-2009-2195)\n",
      "\n",
      "  - A vulnerability in Safari may let a malicious website to\n",
      "    be promoted in Safari's Top Sites. (CVE-2009-2196)\n",
      "\n",
      "  - A vulnerability in how WebKit renders an URL with look-\n",
      "    alike characters could be used to masquerade a website.\n",
      "    (CVE-2009-2199)\n",
      "\n",
      "  - A vulnerability in WebKit may lead to the disclosure of\n",
      "    sensitive information. (CVE-2009-2200)\n"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3733"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/aug/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/17616"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Safari 4.0.3 or later."
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/11"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/11"
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

  exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


function exec(cmd)
{
  local_var buf, ret;

  if (islocalhost())
    buf = pread(cmd:"bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(0);
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(0);

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0);

uname = get_kb_item("Host/uname");
if (!uname) exit(0);


# Mac OS X 10.4 and 10.5.
if (egrep(pattern:"Darwin.* (8\.|9\.[0-8]\.)", string:uname))
{
  cmd = 'cat /Applications/Safari.app/Contents/Info.plist|grep -A 1 CFBundleGetInfoString| tail -n 1 | sed \'s/<string>\\(.*\\)<\\/string>.*/\\1/g\'|awk \'{print $1}\'|sed \'s/,//g\'';
  version = exec(cmd:cmd);
  if (!strlen(version)) exit(1, "Failed to get version of Safari.");
  version = chomp(version);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    ver[0] < 4 ||
    (ver[0] == 4 && ver[1] == 0 && ver[2] < 3)
  )
  {
    if (get_kb_item("global_settings/report_verbosity") > 0)
    {
      report = string(
        "\n",
        "Nessus collected the following information about the current install\n",
        "of Safari on the remote host :\n",
        "\n",
        "  Version : ", version, "\n"
      );
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
  }
  else exit(0, "The remote host is not affected since Safari " + version + " is installed.");
}
