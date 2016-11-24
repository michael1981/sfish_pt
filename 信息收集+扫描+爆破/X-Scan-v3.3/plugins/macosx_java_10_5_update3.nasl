#TRUSTED 7b2ac119f1fa4b4254126817f7148a85074a03170eb33935e6d7855854e81861ecbd0daf36fe3924e33a71066501f5190d0ab2cbd70da200943274f058612bffda172040f82b2657d0eb01c7003fdf28fb6fc230df2bd070e80f5a0b22101aa2d7d9b2be750dfcc26e8609768b313e9b553335dbe9e34acf7c18a1724c0da3d36d5f562e1862a13ea9e55e39593f0fa690fb9e8f7242b159101197cf141bad24591a67b0b44679b35ca80bf2520830c078a8dc543382e401e6728541202e928fd1e5ac06c660409876707e5cb3fe3f32c40766ef57c2de60f2434d73cdab11e11b609e5a0869b68550a0076530efbf4088002c3ae8a645cbf5fe46a999b949b3ffeb8c281095587b318f058cc30da3e88eba8b876ba08ec10a2364cbec0524d01e87c501c4e525cb790643d5ac189eeebe8253c4db140979804d81de4253136cd678f5e37b24c1ba2b384899dcb8569f24760cd46e7d469181f261f495d79ced02ff3fee6b8ecbc736bed0f546f8df58bb1b45ed72274d61fc476616f1c30aec75fe33547dc37936b835c6b314b538878b75fe64d7cd68e5e96d849557affc849d84c089a5eed1462f73f6ebc7b24c2f30d29938ca4243c30a33d0606078eeba3d7ec466396d24d9616105167b59d8a54a929084fe728cca0a736134f9dbd380e77892fccc9de5d1da827e069c098aaf159f2a1abedf81527d73c1e5060b84e2
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);



include("compat.inc");

if (description)
{
  script_id(35686);
  script_version("1.1");

  script_cve_id(
    "CVE-2008-2086",
    "CVE-2008-5340",
    "CVE-2008-5342",
    "CVE-2008-5343"
  );
  script_bugtraq_id(32892);

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 3");
  script_summary(english:"Checks for Java Update 3 on Mac OS X 10.5");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");

 script_set_attribute(attribute:"description", value:"
The remote Mac OS X 10.5 host is running a version of Java for Mac OS
X that is missing Update 3. 

The remote version of this software contains several security
vulnerabilities in Java Web Start and the Java Plug-in.  For instance,
they may allow untrusted Java Web Start applications and untrusted
Java applets to obtain elevated privileges.  If an attacker can lure a
user on the affected host into visiting a specially crafted web page
with a malicious Java applet, he could leverage these issues to
execute arbitrary code subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3437" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2009/feb/msg00003.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.5 Update 3." );
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


# Mac OS X 10.5 only.
uname = get_kb_item("Host/uname");
if (egrep(pattern:"Darwin.* 9\.", string:uname))
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

  # Fixed in version 12.2.2.
  if (
    ver[0] < 12 ||
    (
      ver[0] == 12 && 
      (
        ver[1] < 2 ||
        (ver[1] == 2 && ver[2] < 2)
      )
    )
  ) security_hole(0);
}
