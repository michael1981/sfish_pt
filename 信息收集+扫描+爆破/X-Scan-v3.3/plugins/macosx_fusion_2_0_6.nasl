#TRUSTED 5ff0074f3c26802a7573edb5a3845a9c40a4bf4953039dc8e1fd3fe4403d94286ba5605585101ce963dbf968aa98dba2cacdf8e3411b5089355e9b7299d54e38676099f6cee3df6a4cabb073b42ed69c3a4017160b80c5dfbbc4d719b1ee64a1683bcc850b410b54df6f4474f44b180d18936621701a4d70200c065baf59c0ee1844538d0eb08add88b2210059dd7edabc34a975ef77079f0383f43a163c1b527287668dd8d115dba04c314cb3026ac2e9ed1920c4e35352026a2a2235b7256bcf9bf664e1b452b1b3d9fabee8e279604245acf3cf2b05bd444de3fa1f0292547042c8cb35f544e0bc57590c9db29879673f8ee5da3f27ccfef2887741abd97fe6188900178bae18722a347d0a4ffaa82bea0b52ba12cb0d351dc8d1c0f7102d20e9661bafc122a2cf50402e3d05a178a4cae97c9a8770116979fec38fba6be8756fda99fc8dd74631258e14db7d66da804323b13b9d800194f0d1f6713435ed2a75ad350c3f12dfc809863290b3374d960f492f103083ab2e9eff260a1ca6a3d3042b4f958738b0a363429b9bf075b25d4633f203d0ba89d312ed93fdb3454ccd00c87d60cbd0419c4fd2fce41d92d776c7053e8ffef7bf385e5ec241164640ceb99d73ad731a78b35cf7f0c3b3bc0513f6d1f442e3897c869ec58d72611ffdfdc6dfd5f508195f17ac89c724bd5e49109c5752e2a94470c45958ad1b79fe02
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(41971);
  script_version("1.2");

  script_cve_id("CVE-2009-3281", "CVE-2009-3282");
  script_bugtraq_id(36578, 36579);
  script_xref(name:"OSVDB", value:"58475");
  script_xref(name:"OSVDB", value:"58476");

  script_name(english:"VMware Fusion < 2.0.6 (VMSA-2009-0013)");
  script_summary(english:"Checks version Fusion");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host has an application that is affected by two security\n",
      "issues."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of VMware Fusion installed on the Mac OS X host is earlier\n",
      "than 2.0.6.  Such versions are affected by two security issues :

  - A vulnerability in the vmx86 kernel extension allows
    an unprivileged userland program to initialize
    several function pointers via the '0x802E564A' IOCTL
    code, which can lead to arbitrary code execution in
    the kernel context. (CVE-2009-3281)

  - An integer overflow in the vmx86 kernel extension allows
    for a denial of service of the host by an unprivileged 
    local user. (CVE-2009-3282)"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2009/000066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/18019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/506891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/506893"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to VMware Fusion 2.0.6 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vulnerability_publication_date", 
    value:"2009/10/02"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/10/02"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/10/02"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread(cmd:"bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(1, "ssh_open_connection() failed.");
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(1, "Failed to get version - '"+buf+"'.");

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");
if ("Install VMware Fusion" >!< packages) exit(0, "VMware Fusion is not installed.");


plist = "/Applications/VMware Fusion.app/Contents/Info.plist";
cmd = string(
  "cat '", plist, "' | ",
  "grep -A 1 CFBundleShortVersionString | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 2.0.6.
if (
  ver[0] < 2 ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] < 6)
)
{
  if (get_kb_item("global_settings/report_verbosity") > 0)
  {
    report = string(
      "\n",
      "Product           : VMware Fusion\n",
      "Installed version : ", version, "\n",
      "Fix               : 2.0.6\n"
    );
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since VMware Fusion "+version+" is installed.");
