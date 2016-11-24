#TRUSTED 96543d4f2b94e2bbdc1ba602a051f28db60e0bd72b877d084891651f49c857d8f5e161f080c46860b1ca65e7f12dabf78d85c2f031d9996fa68954d49b3ac81435f9d679687f919454a6e4bf1846683a6c0e539468e6a53a0b1e5a854ee9e264cd2e859c9b38f653025212a284d086284de847987fb8cedb4066221cd2555e94371c48c40c0550bc1e1abe49a31b1aecfb4ecd424106b48c041fc388b19b3fe68896fae338ed1b543e77019187063139902f2089de5708977f307545614f5339e74c9da2cfd9a0f9e425e8ead9dbe01e072714172e98053c9777bf0ba0bf5124199f8bdf47d0032861add4c064b6d82021cf8de0643f59623bc819c03f8360bc34f2daea04d58e31f5fd56b0f5c538ae6fa04cb922663838eceb387ae42dba78db7219f291316b8c14e700bbd1eddec3f914625125d3f8cd9dc73af14ebc03ecbc866fd1a5f6b3ade21618deb7b47ec01c914586056a20e2fdc2b761f17944babfad224d392bfff80679f94709b45238e8b74a82198f98c805042eab078e5c19ff699b60dad53eecf3dd50d27749798c0a300b5aed829b4d22b72475ccbf02d68afc1f7c9791810450c200acfa272caad943142e16e887b417801232970f26b4702f4991efae555ef67c24e3464882ee4b2ee367f5fa0825d074fd23e6e123ef2708a7d4339c91359da1c3c4a8b24db9eb1a9924d959f8b4c014f2fa716186fa
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(40480);
  script_version("1.2");

  script_cve_id("CVE-2009-2198");
  script_bugtraq_id(35926);
  script_xref(name:"OSVDB", value:"56738");

  script_name(english:"Mac OS X : GarageBand < 5.1");
  script_summary(english:"Checks the version of GarageBand");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host has a version of GarageBand that is affected by an\n",
      "information disclosure vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote Mac OS X 10.5 host is running a version of GarageBand older\n",
      "than 5.1.  When such versions are opened, Safari's preferences are\n",
      "changed from the default setting to accept cookies only for the sites\n",
      "being visited to always except cookies.  This change may allow\n",
      "third-parties, in particular advertisers, to track a user's browsing\n",
      "activity."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2009/aug/msg00000.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Upgrade to GarageBand 5.1 or later and check that Safari's preferences\n",
      "are set as desired."
    )
  );
  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/03"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/03"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/04"
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


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "KB item 'Host/MacOSX/packages' not found.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "KB item 'Host/uname' not found.");

# Mac OS X 10.5 only.
if (egrep(pattern:"Darwin.* 9\.", string:uname))
{
  cmd = GetBundleVersionCmd(file:"GarageBand.app", path:"/Applications", long:FALSE);

  if (islocalhost()) 
    version = pread(cmd:"bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(1, "Can't open SSH connection.");
    version = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  if (!strlen(version)) exit(1, "Failed to get version of GarageBand.");
  version = chomp(version);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Fixed in version 5.1.
  if (
    ver[0] < 5 ||
    (ver[0] == 5 && ver[1] < 1)
  )
  {
    if (get_kb_item("global_settings/report_verbosity") > 0)
    {
      report = string(
        "\n",
        "The installed version of GarageBand is ", version, ".\n"
      );
      security_note(port:0, extra:report);
    }
    else security_note(0);
  }
  else exit(0, "The remote host is not affected since GarageBand "+version+" is installed.");
}
