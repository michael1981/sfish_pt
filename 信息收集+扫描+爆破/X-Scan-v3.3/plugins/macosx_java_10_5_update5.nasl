#TRUSTED 203bdc51d653730d1e6de8a18db225603c38bd1ec628084086318773cf52ec8659a5f426920ed8699c919e1ff8a2c8a792011caac13b09cfc078d6a12d99e9548e617af0be6728da3053b52478d35e9b31d79b8c9faf8d8a66143db94630c06c689c639d3dc762673d06de6a3aaa753e2a0e97cf90911ab3d63cec158df705881bbfc13caa06f18a734668072bb0d7bf5649664a9204b04fef55083f6990e7a0fc337e9bc8deb3d71927b5e6a78e2ad7fb7da5a2834f98f6f4f6938aeba3cdb5eac32d4ed89c19bf4a3a06a9542caadc3f7cfdc7ca8af73c8e5d764238ec8ae8f73656583aec45968c8191f29851a9fa3de5af8269e2d4e67721b0fb4aee83dba9ccbad3ef5d28ddf8922a0d9824a3efbd415a8ec1e6c9d075e1ef6a082200e46b3098313d1e42aa1b4e79b9686806beab1210892e4d932913e7bda34806db442b9acf88b30a0c201ff179f397d2d0a44809a2d2012be47272790986f87cf8a4fc0effc05d4fd4e5832f8047f562ad864e96e658361fc1b31009440bd6f44e745570859d7aa361a28dc6ed3b4a82dded6ce31a77c3592b78d27cbfe0ba51b74078a21ebe97ca819cb7d865f444c5bb791e4fde90c16f07505dd19c7c400e4509d681a55cf3611bc8bf74655595177d0092c90263ccadd091fd665e38c65814067b532e8d6d954e09621f223ca924fe36ed754d6cd536b7c948ac29566e07b0c1
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(40873);
  script_version("1.3");

  script_cve_id(
    "CVE-2009-0217",
    "CVE-2009-2205",
    "CVE-2009-2475",
    "CVE-2009-2476",
    "CVE-2009-2625",
    "CVE-2009-2670",
    "CVE-2009-2671",
    "CVE-2009-2672",
    "CVE-2009-2673",
    "CVE-2009-2674",
    "CVE-2009-2675",
    "CVE-2009-2689",
    "CVE-2009-2690",
    "CVE-2009-2722",
    "CVE-2009-2723"
  );
  script_bugtraq_id(35671, 35939, 35942, 35943, 35958);
  script_xref(name:"OSVDB", value:"56243");

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 5");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host has a version of Java that is affected by multiple\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote Mac OS X host is running a version of Java for Mac OS X\n",
      "10.5 that is missing Update 5.\n",
      "\n",
      "The remote version of this software contains several security\n",
      "vulnerabilities, including some that may allow untrusted Java applets\n",
      "to obtain elevated privileges and lead to execution of arbitrary code\n",
      "with the privileges of the current user."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2009/sep/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/17819"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.5 Update 5 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/09/03"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/09/03"
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
    if (!ret) exit(0);
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(0);

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

# Mac OS X 10.5 only.
if (!egrep(pattern:"Darwin.* 9\.", string:uname)) exit(0, "The remote Mac is not affected.");

plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd = string(
  "cat ", plist, " | ",
  "grep -A 1 CFBundleVersion | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 12.4.1.
if (
  ver[0] < 12 ||
  (
    ver[0] == 12 && 
    (
      ver[1] < 4 ||
      (ver[1] == 4 && ver[2] < 1)
    )
  )
)
{
  if (get_kb_item("global_settings/report_verbosity") > 0)
  {
    report = string(
      "\n",
      "Product           : Java for Mac OS X 10.5\n",
      "Installed version : ", version, "\n",
      "Fix               : 12.4.1\n"
    );
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM framework version "+version+" is installed.");
