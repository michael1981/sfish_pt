#TRUSTED 89084ac744ceb431244e47ccae27b0e17a36f795f11a3319de9c2d595a1011a092f4648ff3cc52331f46e8ee7aef16879850f53bab53af7bd5632cc46b7bb80819f88dffe0bff47349bef96d5dc9d4f0ee7d9d593ecb9d7ec4d9605b9a544b3eb1a028909225485f638115b47be2ba8bd9e2c902b2b8e57c7f5cf6727e74985f23db964315a8bd36ef44e59d3c4b18887b80cd7914db2bb60abb6908d894fba3aa48f712f482e6b91ed4cbbda4817957bcbbda560c9c5ccda72f9a6ce725724a604a8d841b9f45d693f0fa3d24b7b3c1c5c175f7f227f33f4d32318fe8eae921fec1a3af99f6c77969cf8ac56b613556b8fe966319fe4dc9fb8c47f528ed9fe2563aeca490c134f029402ad7124dcc386e885c1d9ef30878b5aff435855099889952c30af63738a3f9ecfc3a459985d7e95c53367567ab2a693f70de0a4b1e974285be6965597568acd2c8305204c4e075711b6db04731bf4501d1cf23d9adce4000669d9062e3f671b70e47a4448e7ba36c9f8c0a8b1d6cdba1a1c57bc67009596d482b8ff949fecf40b88ed96b30e6fe014e3a53f06f3af4b076ac2476b7d8d6846424bbd4ad7f0a545e38e4f822b987892790633cbd211902e6d1210d0ae0334a501d105c1c126a91fbfedced4c682bdd85e45f72034f815835b624ab7476b1462ec1dbf7d2df32392e7330e3db81e6343540a0f9f559fce2b0765ff45a80
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);



include("compat.inc");

if (description)
{
  script_id(35685);
  script_version("1.1");

  script_cve_id(
    "CVE-2008-2086",
    "CVE-2008-5340",
    "CVE-2008-5342", 
    "CVE-2008-5343"
  );
  script_bugtraq_id(32892);

  script_name(english:"Mac OS X : Java for Mac OS X 10.4 Release 8");
  script_summary(english:"Check for Java Release 8 on Mac OS X 10.4");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.4 host is running a version of Java for Mac OS
X older than release 8. 

The remote version of this software contains several security
vulnerabilities in Java Web Start and the Java Plug-in.  For instance,
they may allow untrusted Java Web Start applications and untrusted
Java applets to obtain elevated privileges.  If an attacker can lure a
user on the affected host into visiting a specially crafted web page
with a malicious Java applet, he could leverage these issues to
execute arbitrary code subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3436" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2009/feb/msg00002.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.4 release 8." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
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


# Mac OS X 10.4.11 only.
uname = get_kb_item("Host/uname");
if (egrep(pattern:"Darwin.* 8\.11\.", string:uname))
{
  plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
  cmd = string(
    "cat ", plist, " | ",
    "grep -A 1 CFBundleVersion | ",
    "tail -n 1 | ",
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
  );
  version = exec(cmd:cmd);
  if (!strlen(version)) exit(0);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Fixed in version 11.8.2.
  if (
    ver[0] < 11 ||
    (
      ver[0] == 11 && 
      (
        ver[1] < 8 ||
        (ver[1] == 8 && ver[2] < 2)
      )
    )
  ) security_hole(0);
}
