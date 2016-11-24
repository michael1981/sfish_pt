#TRUSTED 58cd1793560e440fe7a06771369317da9d5762d7b504aca86e04c658d2cb15c5541dc87295bda707d75ab249b9ba5959444813f126d1df2bb43c11fc0dde9871c9f8d8ad10d506b0befbd5e0a99f04fa36a2dd2f279dcb2f2e2bc7c976949aba401b63ba5d2639e026c29ce419b30cfe544d4668a404318ede7ca7b18fa0cc1e6eb0dd4386d61c648c15e04c16ef31611a477c6bdbb31fd99201c65e269c336491d3b3d410e85014ba5be0e4da1cce07240f97ac4300cfad5f07a48ed3fb8aa16d46b47df5491a987014678a6cb9ad42027f2e057fe9931eee3360c50807cea5db9bd4c0860d41264d1021c3958415035f2668a770c30a07100183b499446f4f67052a785e3caa009cfbb2839cf6442185805da081cfde6d7ef0e2ea54934058415478c355a43b28f349034317eeec667a670d64019aef815ec7431217a7df512f295147a55c04e7e7c515cea304fc9d6ac1a65b57242bed62752655a9defdbca7c382944bc921f20fdb28aabcc2d492245ebe6846622e7d8d9a418125dbdee9537eda35fbff5b6b1774a6cfbffd534b0175cdcd10a7fa2371c352a5af0e72af4474982094e7be2c019f3beb0d344363d5d2947fee065542bf332997b1798d8815c1e3be264e5c056e31e9b646c3a93668748f556db7c09ad06f79b429c4536dfa86331ec55bac79f275a5007907ac196fc98823d7d83aac1b7da72fdb31d089
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);



include("compat.inc");

if (description)
{
  script_id(33286);
  script_version("1.3");

  script_cve_id("CVE-2008-2307");
  script_bugtraq_id(29836);
  script_xref(name:"OSVDB", value:"46502");
  script_xref(name:"Secunia", value:"30801");

  script_name(english:"Mac OS X : Safari < 3.1.2");
  script_summary(english:"Check the Safari SourceVersion");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by a buffer
overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Safari installed on the remote host reportedly has a
memory corruption issue in WebKit's handling of JavaScript arrays. " );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT2165" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/jun/msg00003.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Safari 3.1.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
 script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 
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

# Mac OS X 10.4
if (egrep(pattern:"Darwin.* (8\.[0-9]\.|8\.1[01]\.)", string:uname))
{
  cmd = 'cat /Applications/Safari.app/Contents/Info.plist|grep -A 1 CFBundleGetInfoString| tail -n 1 | sed \'s/<string>\\(.*\\)<\\/string>.*/\\1/g\'|awk \'{print $1}\'|sed \'s/,//g\'';
  buf = exec(cmd:cmd);
  if (buf !~ "^[0-3]\.") exit(0);

  array = split(buf, sep:'.', keep:FALSE);
  if (
    int(array[0]) < 3 ||
    (int(array[0]) == 3 && int(array[1]) < 1) ||
    (int(array[0]) == 3 && int(array[1]) == 1 && int(array[2]) < 2)
  ) security_hole(0);
}
