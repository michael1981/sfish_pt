#TRUSTED 2247dcd4ba0c183c635b5a6f900b219d1b4dac58929cc7a6f4573ab06bbc07e6b3f3f222391d8f421f34cb0143efd58b54e4e12b1e2ff9f78a49e9551ae35476404eca259557b6d2cd036a78450274fb81d194b238487545a63a6cd3b25eaa70a24de55aada485e3de23fff08b52b621b6ec5cfeb61bf06044f4ac1f79127e133b8a6dd0ffd9291da48b37a15db7ecc0f8814479c307dd4cb55e28061483e399bcc8b0112f992420b5659b00785f44cdc88e7e587d48c4ca8fa717db93ecf4ed766ce2b30e50b9faa2633a198b4ef088c52fa8d0aef818bb8a53482bf41c4f8c511b2aa1bca23112965c22453fdccc2847ab407eab346711c60d3d48bd9e4083ceb93e87f1d4556c02109d19a49c306eed15e02c108274ff49791f6487cf7b8cf6220dee29565e8f386df617c20757c237f00573a5d14d8688cc4951f369ab540ac93483d8255e4f698bd10bd926c65b8c3d6c32d9269db14be78d7c4935fcb9780aa1cf99de4e58874f8bdb5010246a4b6a22476cfac6fdafaeb0b7a5e325c46340e7abe80c12de07e83bc6d58d229db3fccd7f141478c2d64af65762e8201f210eb745427aba3509a47b255aee8de728404bb6d8a7e025cb4e4bfc8815f6c7576e3088a90254ecc2004a85d6517fa05e2ec340d0be7ed7dbbaec3dd04c8697359d72b0c9064031d01930fbe59de591df20b4ce494459f976d9c9ea59138237
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(39768);
  script_version("1.2");

  script_cve_id("CVE-2009-1724", "CVE-2009-1725");
  script_bugtraq_id(35441, 35607);
  script_xref(name:"OSVDB", value:"55738");
  script_xref(name:"OSVDB", value:"55739");

  script_name(english:"Mac OS X : Safari < 4.0.2");
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
      "than 4.0.2  Such versions are potentially affected by two issues :\n",
      "\n",
      "  - A vulnerability in WebKit's handling of parent and top\n",
      "    objects may allow for cross-site scripting attacks.\n",
      "    (CVE-2009-1724)\n",
      "\n",
      "  - A memory corruption issue in WebKit's handling of\n",
      "    numeric character references could lead to a crash or \n",
      "    arbitrary code execution. (CVE-2009-1725)"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3666"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/jul/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/17297"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Safari 4.0.2 or later."
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/07/08"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/09"
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
if (egrep(pattern:"Darwin.* (8\.|9\.([0-6]\.|7\.[01][^0-9]))", string:uname))
{
  cmd = 'cat /Applications/Safari.app/Contents/Info.plist|grep -A 1 CFBundleGetInfoString| tail -n 1 | sed \'s/<string>\\(.*\\)<\\/string>.*/\\1/g\'|awk \'{print $1}\'|sed \'s/,//g\'';
  version = exec(cmd:cmd);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    ver[0] < 4 ||
    (ver[0] == 4 && ver[1] == 0 && ver[2] < 2)
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
}
