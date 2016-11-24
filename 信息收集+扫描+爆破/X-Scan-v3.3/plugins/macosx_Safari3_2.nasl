#TRUSTED 940f3e3f08745bea9cc95eea1b4c82446f2013e2eef1a7e069f3ecf267cf24e2e6ab69f159b6aa16bf3d83876c749b032e97ba120560b34c99040941ef2367a480909bf554ad87a8380cd2a3239b0de4842630ab18410c86bbea08005a02dc855cc3b9673dbba5669d18ea7697c04ce5b00b74c23241f29eba32130ba41151106510312a69aebb13b3eb10f2926b9fac07773a386d1783471111d0d339a21156fcaf6ded96ebb78938030dcf705fc7c0267abf4f7326cf00e723bbfc3cbe7ce91256c4ea412d431d4e412175179970368c65cc9b9e99f9019e0dcd1606fed19af9fa09877d624a50038a9043867421f6d50cdc72f420a5f3ba4df896ff7698f2718dc7c924bfc4d793724c4c7ddcaccff1167732ee0a5bc0bac103d76e2236fcc827c850a9ee9c77a4f72b0909bf74246ad1e5fc4db9473691663e54075fa8043a8b480fe7623e18a0b4e543a00a4999c0f4f04d5f246327265cb5164c22708325ae894848d9cb95ace067657741a4d834ead972f590d4abb3fbd87e152b1f9139213df62764fe44949cae03f7567bbdf3ffd50ad51c2f3e4b5b1cf18fb24b3f52d46ad3c88194d51cd9eb661511fe364d08b85885d9644f622c1aa8dc0d619bb123b8ee05c1fdcb447f5bda792eda1590d9fa8af4f50ddc8c8dc04f827ac45500572e91b8f2003053ac4fcbddd33bc636e9a9dfd39dd4db1136337d5087326c
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);



include("compat.inc");

if (description)
{
  script_id(34773);
  script_version("1.2");

  script_cve_id(
    # "CVE-2005-2096",
    # "CVE-2008-1767",
    "CVE-2008-2303",
    "CVE-2008-2317",
    # "CVE-2008-2327",
    # "CVE-2008-2332",
    # "CVE-2008-3608",
    # "CVE-2008-3623",
    # "CVE-2008-3642",
    "CVE-2008-3644",
    "CVE-2008-4216"
  );
  script_bugtraq_id(32291);
  script_xref(name:"OSVDB", value:"47289");
  script_xref(name:"OSVDB", value:"47290");
  script_xref(name:"OSVDB", value:"49940");
  script_xref(name:"OSVDB", value:"49941");

  script_name(english:"Mac OS X : Safari < 3.2");
  script_summary(english:"Check the Safari SourceVersion");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Safari installed on the remote Mac OS X host is earlier
than 3.2.  Such versions are potentially affected by several issues :

  - A signedness issue in Safari's handling of JavaScript 
    array indices could lead to a crash or arbitrary code 
    execution. (CVE-2008-2303)

  - A memory corruption issue in WebCore's handling of style
    sheet elements could lead to a crash or arbitrary code 
    execution. (CVE-2008-2317)

  - Disabling autocomplete on a form field may not prevent 
    the data in the field from being stored in the browser 
    page cache. (CVE-2008-3644)

  - WebKit's plug-in interface does not block plug-ins from 
    launching local URLs, which could allow a remote 
    attacker to launch local files in Safari and lead to the 
    disclosure of sensitive information. (CVE-2008-4216)" );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3298" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/nov/msg00001.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/15730" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Safari 3.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2008 Tenable Network Security, Inc.");
 
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
if (egrep(pattern:"Darwin.* (8\.|9\.([0-4]\.|5\.0))", string:uname))
{
  cmd = 'cat /Applications/Safari.app/Contents/Info.plist|grep -A 1 CFBundleGetInfoString| tail -n 1 | sed \'s/<string>\\(.*\\)<\\/string>.*/\\1/g\'|awk \'{print $1}\'|sed \'s/,//g\'';
  buf = exec(cmd:cmd);
  if (buf !~ "^[0-3]\.") exit(0);

  array = split(buf, sep:'.', keep:FALSE);
  if (
    int(array[0]) < 3 ||
    (int(array[0]) == 3 && int(array[1]) < 2) 
  ) security_hole(0);
}
