#TRUSTED 5ffc345a13d44e8f6b8954846fd6d7ec7d656ab64d47228becba49e4c2f33e48476db24a2018e951ac77b2909d88595b3cb0835b4a0d488e5220fb6468cba3048e0f84259cbe4cbff48b7a492f902d385eb39b41db75ff9f312d942fc946c016534b7436c3b65af88e7bce9ed176724453ee4fce72ad74e328b7373af86a78a2e6820c927f20c564cb4a72313e8de2adfa75b77aef97025bb7818bd9b1086f1c76421bbf56206dfd3c03ba40824a3b781006f011992358d4b70512be6e52ca0de6adbd20bc3f47b511565d428e279c4c48b2932757e10bfd61de61809cd3777f53896d34237261857a76d04df6ac26d38969cbb00399b5ce2448cdd78a2eeaca8c91edf2f710bfa95efd7d27c34c4d0f953514f37c98de5872b4d93185a158f70246c40f223761bb5078a1c4ad120dfadc3d592ed4c7643ba92fb0bea106169875fe7654d8a1d6dbacef748ebeba8ebe1ef730ab62fa2344c8b2a3c2d8bf14fad1ad1a98ac06038b2f1e77f04f3a81452a47c304598692c93da56bb28439f946726ea802c7115b9b02e119dc7cddbe03fd61f35564a7957b39b5d784818ed2ae99641e8ed53599390d84a1bb3a81651ee439a621ac8075c331f0e0dc4dca1340fbd100cf5d0518ad7b533544c500363ed1dd76d1a883e5cadb824aace7eae0bae8bbaf6027c41088c6e4740d8bc79522c5cfbf3625a541238a680e96cadad3c9
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33851);
 script_version ("1.3");
 script_name(english: "Network daemons not managed by the package system");
 
 script_set_attribute(attribute:"synopsis", value:
"Some server processes on the remote host are associated with programs  
that have been installed manually." );
 script_set_attribute(attribute:"description", value:
"Some server processes on the remote host are associated with programs  
that have been installed manually.

Sound system administration practice dictates that an operating  
system's native package management tools be used to manage software  
installation, updates, and removal whenever possible.

Make sure that manual software installation is authorized by your 
organization's security policy." );
 script_set_attribute(attribute:"solution", value:
"Use packages supplied by your system vendor whenever possible." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:N/I:P/A:N" );


script_end_attributes();

 script_summary(english: "Checks that running daemons are registered with RPM or dpkg");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008 Tenable Network Security, Inc.");
 script_family(english: "Misc.");
 script_require_keys("Host/uname");
 script_dependencies("ssh_get_info.nasl", "process_on_port.nasl");
 exit(0);
}

include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");


uname = get_kb_item("Host/uname");
if ( ! uname || "Linux" >!< uname ) exit(0);


pkg_system = NULL;

# We cannot solely rely on the fact that the 'rpm' command is installed (it can be 
# installed on Debian or Gentoo for instance).
#
# Although there are other RPM based distros, we do not support them to 
# avoid FP.
v = get_kb_list('Host/*/rpm-list');
if (! isnull(v)) pkg_system = "RPM";
else
{
 v = get_kb_list('Host/*/dpkg-l');
 if (! isnull(v)) pkg_system = 'dpkg';
 else
 {
  v = get_kb_item('Host/Gentoo/qpkg-list');
  if (strlen(v) > 0) pkg_system = "emerge";
  else
  {
   exit(0);	# Unsupported distro
  }
 }
}

v = NULL;	# Free memory


full_path_l = get_kb_list("Host/Daemons/*/*/*");
if (isnull(full_path_l)) exit(0);
full_path_l = make_list(full_path_l);
if (max_index(full_path_l) == 0) exit(0);

# We may support other protocols here
if ( islocalhost() )
 info_t = INFO_LOCAL;
else
{
 ret = ssh_open_connection();
 if (! ret ) exit(0);
 info_t = INFO_SSH;
}

prev = NULL;
bad = ""; bad_n = 0;
foreach d (sort(full_path_l))
  if (strlen(d) > 0 && d != prev && d[0] == '/' )
  {
    prev = d;
    d = str_replace(find:"'", replace:"'\''", string:d);
    if (pkg_system == 'RPM')
    {
      buf = info_send_cmd(cmd: strcat('LC_ALL=C rpm -q -f \'', d, '\' || echo FileIsNotPackaged'));
      if ("FileIsNotPackaged" >< buf || strcat("file ", d, " is not by any package") >< buf)
      {
        bad = strcat(bad, d, '\n');
	bad_n ++;
      }
    }
    else if ( pkg_system == "dpkg" )
    {
      buf = info_send_cmd(cmd: strcat('LC_ALL=C dpkg -S \'', d, '\' || echo FileIsNotPackaged'));
      if ("FileIsNotPackaged" >< buf || strcat("dpkg: ", d, " not found.") >< buf)
      {
        bad = strcat(bad, d, '\n');
	bad_n ++;
      }
    }
    else if (pkg_system == "emerge")
    {
      buf = info_send_cmd(cmd: strcat('LC_ALL=C fgrep -q \'obj ', d, ' \' /var/db/pkg/*/*/CONTENTS || echo FileIsNotPackaged'));
      if ("FileIsNotPackaged" >< buf)
      {
        bad = strcat(bad, d, '\n');
	bad_n ++;
      }
    }
    else exit(0); # ?
  }

if (bad_n > 0)
{
  if (bad_n <= 1)
    report = 'The following running daemon is not managed by ';
  else
    report = 'The following running daemons are not managed by ';
  report = strcat(report, pkg_system, ' :\n\n', bad);
  security_note(port: 0, extra: '\n' + report);
}
