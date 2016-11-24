#TRUSTED 54c48e9b870a7c3caf491700ec6f5d01145608a6678fd8dff568fe267f44122b20e694e14bc72806cffd41c6b8f91ed291f0d554aaad7b5319431996ee07263280a8f84e2767f8e47be9443341b46877018b41fabf0ffddd6ce21d88c51f1dce1e45535f24ef4afe11444d5e9d9e3424854a82409bf062110efef0ceb495f9f1325a087a236a2eec276ef3b50e465c5c41f918b68648b978b610598e616d482d0ffd35210bc346c18d20336b6257c528cd14439386f903a439bbf01a05b5be80b906af58c8eaac32fda5c81ba11ba2d61229636fdf969cbc07660927b8b10dbd11729c82099305b8a3ef75f98b6424f2346ed5eaa0ddc53762689ce58cc751ddc472f1232e8428cf16153041b6db644f354facb4e86b01d6efb663fbc6a365b271d2e16ef7fb76014d2fcd06ef0034c1671d1105f06a6459e9587b2dabfc53d2996196709a24b615c968515ce40b2d370c47ee638128b8f3ebc212e8ede461eaecb2775227326eb09ea8b38e986968762f5c7a03550c1f64e9f279c25cfd85a5f11d247c3af3828dcfec42005aac8e7c6d406df071ce0ca539f5fce4dc611562d5d245ec0e7cfe90b55a4d4e08667e795de334fe4e1444ddc81973d3bb390c78e3b9a077dc74c941d388297546e268efe43b666dc2a5d205c39b51809376d1423512f08b4e515640ec0bfb7a160142c8071630aa69180cc9f23c84f045b4b189
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(12634);
 script_version ("2.33");
 
 script_name(english:"Authenticated Check: OS Name and Installed Package Enumeration");
 script_summary(english:"Obtains the remote OS name and installed packages");
 
 script_set_attribute(
  attribute:'synopsis',
  value:string(
   "This plugin gathers information about the remote host via an\n",
   "authenticated session."
  )
 );
 script_set_attribute(
  attribute:'description',
  value:string(
   "This plugin logs into the remote host using SSH, RSH, RLOGIN, Telnet\n",
   "or local commands and extracts the list of installed packages.\n",
   "\n",
   "If using SSH, you should configure the scan with a valid SSH public\n",
   "key and possibly an SSH passphrase (if the SSH public key is protected\n",
   "by a passphrase)."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:"n/a"
 );
 script_set_attribute(
  attribute:"risk_factor", 
  value:"None"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2004/07/06"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Settings");
 
 script_dependencies("find_service1.nasl", "ssh_settings.nasl", "clrtxt_proto_settings.nasl");
 # script_require_ports(22, "Services/ssh", 23, "Services/telnet", 512, 513, 514);
 exit(0);
}


include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

#### Gentoo function ####

function extract_gentoo_portdir(buf)
{
  local_var	lines, portdir, gr, len;

  gr = egrep(string: buf, pattern: '^[ \t]*PORTDIR[ \t]*=[ \t]*');
  # Keep the last line, just in case
  lines = split(gr, keep: 0);
  portdir = lines[max_index(lines)-1];
  lines = split(portdir, sep: '=', keep: 0);
  portdir = lines[1];
  len = strlen(portdir);
  if ( portdir[0] == "'" && portdir[len-1] == "'" ||
       portdir[0] == '"' && portdir[len-1] == '"' )
   portdir = substr(portdir, 1, len-2);
  return portdir;
}


#------------------------------------------------------------------------#
# Misc calls (all Unixes)						 #
#------------------------------------------------------------------------#

# cfengine version 

function misc_calls_and_exit()
{
 local_var buf, cmd, error_msg, ver;
 global_var release;

 ver = info_send_cmd(cmd:"/usr/sbin/cfservd --help | grep ^cfengine | cut -d '-' -f 2");
 if ( ver )
  {
   ver = chomp(ver);
   set_kb_item(name:string("cfengine/version"), value:ver);
  }

 if ("AIX-" >< release) cmd = '/etc/ifconfig -a';
 else cmd = '/sbin/ifconfig -a';
 buf = info_send_cmd(cmd:cmd);

 if ( buf ) set_kb_item(name:"Host/ifconfig", value:buf);

 if (info_t == INFO_SSH) ssh_close_connection();
 exit(0);
}

report = "";
info_t = 0;

#### Choose "transport" ####


error_msg = "";
ssh_failed = 0; 
telnet_failed = 0;
port_g = NULL; 
sock_g = NULL;

if (islocalhost() && defined_func("fread") && defined_func("pread"))
{
 info_t = INFO_LOCAL;
 set_kb_item(name: 'HostLevelChecks/proto', value: 'local');
 if ( defined_func("report_xml_tag") ) report_xml_tag(tag:"local-checks-proto", value:"local");
}

if (! info_t)
{
 if (defined_func("bn_random"))
 {
  port22 = kb_ssh_transport();
  sock_g = ssh_open_connection();
  private_key = kb_ssh_privatekey();
 }
 if (sock_g)
 {
  info_t = INFO_SSH;
  set_kb_item(name: 'HostLevelChecks/proto', value: 'ssh');
  if ( defined_func("report_xml_tag") ) {
	report_xml_tag(tag:"local-checks-proto", value:"ssh");
        report_xml_tag(tag:"ssh-login-used", value:kb_ssh_login());
	if ( kb_ssh_privatekey() )
		report_xml_tag(tag:"ssh-auth-meth", value:"private-key");
	else
		report_xml_tag(tag:"ssh-auth-meth", value:"password");
  }
  port_g = port22;
 }
 else 
 {
  ssh_failed = 1;
  if ( kb_ssh_login() && ( kb_ssh_password() || kb_ssh_privatekey() )  ) 
  {
    set_kb_item(name: 'HostLevelChecks/ssh/failed', value:TRUE);
    error_msg = get_ssh_error();
    if (error_msg) set_kb_item(name: 'HostLevelChecks/ssh/error_msg', value:TRUE);
  }
  try_telnet = get_kb_item("HostLevelChecks/try_telnet");
  try_rlogin = get_kb_item("HostLevelChecks/try_rlogin");
  try_rsh    = get_kb_item("HostLevelChecks/try_rsh");
  try_rexec  = get_kb_item("HostLevelChecks/try_rexec");
  login      = get_kb_item("Secret/ClearTextAuth/login");
  pass       = get_kb_item("Secret/ClearTextAuth/pass");
 }
}


if (! info_t && try_rlogin && strlen(login) > 0)
{
 port513 = get_kb_item("Services/rlogin");
 if (! port513) port513 = 513;

 sock_g = rlogin(port: port513, login: login, pass: pass);
 if (sock_g)
 {
  info_t = INFO_RLOGIN;
  set_kb_item(name: 'HostLevelChecks/proto', value: 'rlogin');
  if ( defined_func("report_xml_tag") ) {
	report_xml_tag(tag:"local-checks-proto", value:"rlogin");
	report_xml_tag(tag:"rlogin-login-used", value:login);
  }
  port_g = port513;
 }
 else
  {
  set_kb_item(name: 'HostLevelChecks/rlogin/failed', value:TRUE);
  rlogin_failed = 1;
  }
}

if (! info_t && try_rsh && strlen(login) > 0 )
{
 port514 = get_kb_item("Services/rsh");
 if (! port514) port514 = 514;
 r = send_rsh(port: port514, cmd: 'id');
 if ("uid=" >< r)
 {
  info_t = INFO_RSH;
  set_kb_item(name: 'HostLevelChecks/proto', value: 'rsh');
  if ( defined_func("report_xml_tag") ) {
	report_xml_tag(tag:"local-checks-proto", value:"rsh");
	report_xml_tag(tag:"rsh-login-used", value:login);
  }
  port_g = port514;
 }
 else
  {
  set_kb_item(name: 'HostLevelChecks/rsh/failed', value:TRUE);
  rsh_failed = 1;
  }
}

if (! info_t && try_rexec && strlen(login) > 0)
{
 port512 = get_kb_item("Services/rexec");
 if (! port512) port512 = 512;
  r = send_rexec(port: port512, cmd: 'id');
 if ("uid=" >< r)
 {
  info_t = INFO_REXEC;
  set_kb_item(name: 'HostLevelChecks/proto', value: 'rexec');
  if ( defined_func("report_xml_tag") ) {
	report_xml_tag(tag:"local-checks-proto", value:"rexec");
	report_xml_tag(tag:"rexec-login-used", value:login);
  }
  port_g = port512;
 }
 else
  {
  set_kb_item(name: 'HostLevelChecks/rexec/failed', value:TRUE);
  rexec_failed = 1;
  }
}


if (! info_t && try_telnet && strlen(login) > 0 && strlen(pass) > 0)
{
 port23 = get_kb_item("Services/telnet");
 if (! port23) port23 = 23;
  sock_g = telnet_open_cnx(port: port23, login: login, pass: pass);
 if (sock_g)
 {
  info_t = INFO_TELNET;
  set_kb_item(name: 'HostLevelChecks/proto', value: 'telnet');
  if ( defined_func("report_xml_tag") ) {
	report_xml_tag(tag:"local-checks-proto", value:"telnet");
	report_xml_tag(tag:"telnet-login-used", value:login);
  }
  port_g = port23;
 }
 else
 {
  set_kb_item(name: 'HostLevelChecks/telnet/failed', value:TRUE);
  telnet_failed = 1;
 }
}

#

if (info_t == INFO_LOCAL)
 report = "Nessus can run commands on localhost to check if patches are applied";
else if (info_t == INFO_SSH && private_key)
	report = "It was possible to log into the remote host using the supplied asymetric keys"; 
else
	report = "It was possible to log into the remote host using the supplied password"; 

if ( info_t == 0 )
{
  if (strlen(error_msg)) exit(1, error_msg);
  else exit(1, "Unknown failure.");
}


# Determine the remote operating system type

# Windows is not supported
if ( info_t == INFO_SSH )
{
 buf = ssh_cmd(cmd: 'cmd /C ver', nosh:TRUE);
 if ( buf && ("Microsoft Windows" >< buf)) exit(0);
}

# 
# Make sure sudo is working
#
if ( NASL_LEVEL >= 3200 )
{
 if ( get_kb_item("Secret/SSH/sudo") )
 {
  buf = info_send_cmd(cmd: 'id');
  if ( ! buf )
  {
    rm_kb_item(name:"Secret/SSH/sudo");
    rm_kb_item(name:"Secret/SSH/sudo-password");
  }
 }
}

buf = info_send_cmd(cmd: 'uname -a');

if ( buf ) set_kb_item(name:"Host/uname", value:buf);
else {
	report += 
'\nHowever the execution of the command "uname -a" failed, so local security
checks have not been enabled';

	if (info_t == INFO_SSH)
	{
         error = ssh_cmd_error();
         if (strlen(error) > 0)
          report += '\n\nNessus return the following error message :\n' + error;
	}

	security_note(port:0, data:report);
	exit(0);
     }


report += '\nThe output of "uname -a" is :\n' + buf;


############################# FreeBSD ###########################################
if ( "FreeBSD" >< buf )
{
  release = ereg_replace(pattern:".*FreeBSD ([0-9]\.[^ ]*).*", replace:"\1", string:buf);
 items = split(release, sep:"-", keep:0);
 if ( "p" >< items[2] ) items[2] = ereg_replace(pattern:"p", replace:"_", string:items[2]);
 release = "FreeBSD-" + items[0] + items[2];
 set_kb_item(name:"Host/FreeBSD/release", value:release); 
 buf = info_send_cmd(cmd: "/usr/sbin/pkg_info");

  if ( ! buf )  {
	report += 
'\nThe command "pkg_info" did not return any results, therefore FreeBSD local 
security checks have not been enabled for this test.';
	security_note(port:0, data:report);
	set_kb_item(name:'HostLevelChecks/failure', value:"'pkg_info' did not return any result");
	}
  else {
        set_kb_item(name:"Host/FreeBSD/pkg_info", value:buf);
	set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
        report += '\nLocal security checks have been enabled for this host.';
	security_note(port:0, data:report);
	misc_calls_and_exit();
	}
}
######################## RedHat Linux ###########################################
else if ("Linux" >< buf )
{
  cpu = info_send_cmd(cmd:"uname -m");
  if (cpu)  set_kb_item(name:"Host/cpu", value: cpu);

  buf = info_send_cmd(cmd: "cat /etc/vmware-release");
  if ( "VMware" >< buf )
  {
   set_kb_item(name:"Host/VMware/release", value:buf);
   patches = info_send_cmd(cmd: "/usr/sbin/esxupdate -l query");
   if ( ! patches )
   {
     report += 
'\nThe command "esxupdate -l query" did not produce any results, therefore local security 
checks have been disabled.';
    security_note(port:0, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'esxupdate -l query' did not return any result");
    exit(0);
   }

   set_kb_item(name: "Host/VMware/esxupdate", value: patches);
   buf = egrep(string: patches, pattern: '^[ \t]*([0-9.-]+|ESXi?[0-9]+-Update[0-9]+)[ \t].*( Update | Full bundle )');
   if (buf)
   {
     last = '';
     foreach line (split(buf, keep: 0))
     {
       v = eregmatch(string: line, pattern: '^[ \t]*([^ \t]+)[ \t]');
       if (! isnull(v))
       {
         pkg = v[1];
	 buf = info_send_cmd(cmd: "/usr/sbin/esxupdate info "+pkg);
	 date = egrep(string: buf, pattern: '^Release Date[ \t]*:', icase: 1);
	 if (date)
	 {
	   v = eregmatch(string: date, pattern: '^Release Date[ \t]*:[ \t]*(20[0-9][0-9]-[012][0-9]-[0-3][0-9])', icase: 1);
	   if (! isnull(v))
	   {
	     date = v[1];
	     if (date > last) last = date;
	   }
	 }
       }
     }
     if (last) set_kb_item(name: 'Host/VMware/NewestBundle', value: last);
   }

   buf = egrep(string: patches, pattern: '[ \t](VMware ESXi? Server|Full bundle of ESXi? [0-9.-]+)[ \t]*$');
   if (buf)
   {
     if (" ESXi " >< buf) e = "ESXi";
     else if (" ESX " >< buf) e = "ESX";
     v = eregmatch(string: buf, pattern: '^[ \t]*([0-9.]+)(-[0-9]+)?[ \t]');
     if (! isnull(v))
       set_kb_item(name: "Host/VMware/version", value: e + " " + v[1]);
   }

   report += '\nLocal security checks have been enabled for this host.';
   set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
   security_note(port:0, data:report);
   misc_calls_and_exit();
  }
  
  buf = info_send_cmd(cmd: "cat /etc/mandrake-release");
  if (buf && "/etc/mandrake-release" >!< buf ) set_kb_item(name: "Host/etc/mandrake-release", value: buf);

  buf = info_send_cmd(cmd: "cat /etc/redhat-release");
  if (buf && "/etc/redhat-release" >!< buf ) set_kb_item(name: "Host/etc/redhat-release", value: buf);
  if ( egrep(pattern:"(Red Hat.*|^Enterprise Linux )(Enterprise|Advanced).*release ([345]|2\.1)", string:buf) ||
       egrep(pattern:"Fedora .*", string:buf) )
  {
   if ( "Red Hat" >< buf ) report += '\nThe remote Red Hat system is :\n' + buf;
   else if ( buf =~ "^Enterprise Linux Enterprise Linux"  ) {
		report += '\nThe remote Oracle Unbreakable Linux system is :\n' + buf;
		buf = ereg_replace(pattern:"^Enterprise Linux", replace:"Red Hat", string:buf);
		set_kb_item(name:"Host/Oracle/Linux", value:TRUE);
		}
   else if ("Fedora" >< buf ) report += '\nThe remote Fedora system is :\n' + buf;
   set_kb_item(name:"Host/RedHat/release", value:buf);
   buf = info_send_cmd(cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");

   if ( ! buf )
   {
     report += 
'\nThe command "rpm -qa" did not produce any results, therefore local security 
checks have been disabled.';
    security_note(port:0, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }

   if ( get_kb_item("Host/Oracle/Linux") )
   {
    lines = split(buf);
    buf = NULL;
    foreach line ( lines )
    {
     if ( line !~ "^kernel-" ) buf += line;
    }
   }

   report += '\nLocal security checks have been enabled for this host.';
   set_kb_item(name:"Host/RedHat/rpm-list", value:buf);
   if ( ! cpu )
   {
     report += 
'\nThe command "uname -m" did not produce any results, therefore local security 
checks have been disabled.';
    security_note(port:0, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'uname -m' did not return any result");
    exit(0);
   }
   set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
   security_note(port:0, data:report);
   misc_calls_and_exit();
  }
 else if ( "CentOS" >< buf )
 {
   set_kb_item(name:"Host/CentOS/release", value:buf);
   buf = info_send_cmd(cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");
   if ( ! buf )
   {
     report += 
'\nThe command "rpm -qa" did not produce any results, therefore local security 
checks have been disabled.';
    security_note(port:0, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }
   set_kb_item(name:"Host/CentOS/rpm-list", value:buf);

   if ( ! cpu )
   {
     report += 
'\nThe command "uname -m" did not produce any results, therefore local security 
checks have been disabled.';
    security_note(port:0, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'uname -m' did not return any result");
    exit(0);
   }
   report += '\nLocal security checks have been enabled for this host.';
   set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
   security_note(port:0, data:report);
   misc_calls_and_exit();
 }
#####################   Mandrake ####################################################
#Mandrake Linux release 9.1 (Bamboo) for i586
  else
  {
  #buf = ssh_cmd(socket:sock, cmd:"cat /etc/redhat-release");
  if (("Mandrake Linux" >< buf && "Mandrake Linux Corporate" >!< buf) || "Mandrakelinux" >< buf || 
	"Mandriva Linux release" >< buf )
  {
   report += '\nThe remote Mandrake system is :\n' + buf;
   version = ereg_replace(pattern:"(Mandrake Linux|Mandrakelinux|Mandriva Linux) release ([0-9]+\.[0-9]) .*", string:egrep(string:buf, pattern:"Mandr(ake|iva)"), replace:"\2");
   set_kb_item(name:"Host/Mandrake/release", value:"MDK" + version);
   
   #report += '\ndebug:\n' + version;
   
   buf = info_send_cmd(cmd:"rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");

   if ( ! buf )
   {
     report +=
'\nThe command "rpm -qa" did not produce any results, therefore local security
checks have been disabled.';
    security_note(port:0, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }

   report += '\nLocal security checks have been enabled for this host.';
   set_kb_item(name:"Host/Mandrake/rpm-list", value:buf);
   set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
   security_note(port:0, data:report);
   misc_calls_and_exit();
  }
  }

###################### SuSE ###############################################################

  buf = info_send_cmd(cmd: "cat /etc/SuSE-release");
  if (buf && "/etc/SuSE-release" >!< buf ) set_kb_item(name: "Host/etc/suse-release", value: buf);

# SuSE Linux Enterprise Server says:
# SuSE SLES-8 (i386)
# VERSION = 8.1
# SuSE pro says:
# SuSE Linux 9.3 (i586)
# VERSION = 9.3
# Version 10.0 on Live CD says:
# SUSE LINUX 10.0 (i586)
# VERSION = 10.0
# SLES9 says:
# Novell Linux Desktop 9 (i586)
# VERSION = 9
# RELEASE = 9

  if (buf && 
      ("suse linux" >< tolower(buf) || "SuSE SLES" >< buf || 
       "opensuse" >< tolower(buf) || "Novell Linux Desktop" >< buf))
  {
    version = '';
    report += '\nThe remote SuSE system is :\n' + egrep(pattern:"^(Novell|(Open)?SuSE)", string:buf, icase:TRUE);
    version = egrep(string: buf, pattern: "^VERSION *= *[0-9.]+$");
    version = chomp(ereg_replace(pattern: "^VERSION *= *", string: version, replace: ""));
    if (! version)
    {
      v = eregmatch(pattern:"SuSE Linux ([0-9]+\.[0-9]) .*", 
		    string:egrep(string:buf, pattern:"SuSE ", icase:1), 
                    icase:TRUE);
      if (! isnull(v)) version = v[1];
    }
    if (! version)
    {
      report += '\nThis version of SuSE Linux could not be precisely identified,\ntherefore local security checks have been disabled.';
      security_note(port:0, data:report);
      set_kb_item(name:'HostLevelChecks/failure', value:"Could not identify the version of the remote SuSE system");
      exit(0);
    }

        if (version <= 9)
	  set_kb_item(name:"Host/SuSE/release", value:"SUSE" + version);
	else if ( "SUSE Linux Enterprise Desktop" >< buf)
	 set_kb_item(name:"Host/SuSE/release", value:"SLED" + version);
  	else if ( "SUSE Linux Enterprise Server" >< buf )
	 set_kb_item(name:"Host/SuSE/release", value:"SLES" + version);
	else
	 set_kb_item(name:"Host/SuSE/release", value:"SUSE" + version);
	buf = info_send_cmd(cmd:"rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");

   if ( ! buf )
   {
     report += 
'\nThe command "rpm -qa" did not produce any results, therefore local security 
checks have been disabled.';
    security_note(port:0, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }

   if ( ! cpu )
   {
     report += 
'\nThe command "uname -m" did not produce any results, therefore local security 
checks have been disabled.';
    security_note(port:0, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'uname -m' did not return any result");
    exit(0);
   }

   report += '\nLocal security checks have been enabled for this host.';
   set_kb_item(name:"Host/SuSE/rpm-list", value:buf);
   set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
   security_note(port:0, data:report);
   misc_calls_and_exit();
  }
  
###################### Gentoo ###############################################

  buf = info_send_cmd(cmd: "cat /etc/gentoo-release");
  if (buf && "/etc/gentoo-release" >!< buf ) set_kb_item(name: "Host/etc/gentoo-release", value: buf);

  if ( buf && "Gentoo" >< buf )
  {
    if ( "Gentoo" >< buf )
      report += '\nThe remote Gentoo system is :\n' + egrep(pattern:"^Gentoo", string:buf);
    version = ereg_replace(pattern:"Gentoo Base System version (([0-9]+\.)*[0-9]+).*",
                             string:egrep(string:buf, pattern:"Gentoo"), replace:"\1");
    # Release does not make much sense on Gentoo
    set_kb_item(name:"Host/Gentoo/release", value: version);

    buf = info_send_cmd(cmd: 'egrep "ARCH=" /etc/make.profile/make.defaults');
    if ( buf )
    {
     buf = ereg_replace(string: buf, pattern: 'ARCH="(.*)"', replace: "\1");
     set_kb_item(name: "Host/Gentoo/arch", value: buf);
    }

    buf = info_send_cmd(cmd: 'readlink /etc/make.profile');
    if (buf)
     set_kb_item(name: "Host/Gentoo/make.profile", value: buf);

    buf = info_send_cmd(cmd: "LC_ALL=C emerge --info");
    if (buf)
    {
      set_kb_item(name: "Host/Gentoo/emerge_info", value: buf);
      portdir = extract_gentoo_portdir(buf: buf);
    }

    buf = info_send_cmd(cmd: "LC_ALL=C cat /etc/make.conf");
    if (buf)
    {
      set_kb_item(name: "Host/etc/make_conf", value: buf);
      if (! portdir || portdir[0] != "/")
        portdir = extract_gentoo_portdir(buf: buf);
    }
    if (portdir)
      set_kb_item(name: "Host/Gentoo/portdir", value: portdir);

    if (! portdir || portdir[0] != "/") portdir = "/usr/portage";
    # Sanitize portdir, just in case...
    portdir = str_replace(find:"'", replace:"'\''", string: portdir);
    buf = info_send_cmd(cmd: "LC_ALL=C cat '"+portdir+"/metadata/timestamp.x'");
    if (buf)
      set_kb_item(name: "Host/Gentoo/timestamp_x", value: buf);

    buf = info_send_cmd(cmd: "LC_ALL=C cat '"+portdir+"/metadata/timestamp'");
    if (buf)
      set_kb_item(name: "Host/Gentoo/timestamp", value: buf);

    # A great idea from David Maciejak: 
    # 1. app-portage/gentoolkit is not necessarily installed 
    # 2. and this find is quicker than "qpkg -v -I -nc"
    # WARNING! We may catch files like -MERGING-* or *.portage_lockfile
    buf = info_send_cmd(cmd:'find /var/db/pkg/ -mindepth 2 -maxdepth 2 -printf "%P\\n"');
    if (buf)
    {
      report += '\nLocal security checks have been enabled for this host.';
      set_kb_item(name:"Host/Gentoo/qpkg-list", value:buf);
      set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
      security_note(port:0, data:report);

      buf = info_send_cmd(cmd: "find /usr/portage/ -wholename '/usr/portage/*-*/*.ebuild' | sed 's,/usr/portage/\([^/]*\)/.*/\([^/]*\)\.ebuild$,\1/\2,'");
      if (buf)
       set_kb_item(name:"Host/Gentoo/ebuild-list", value: buf);
    }
    else
    {
      report += 
'For any reason, find did not produce any results, therefore local security 
checks have been disabled.';
     set_kb_item(name:'HostLevelChecks/failure', value:"'find /var/db/pkg/' did not return any result");
     security_note(port:0, data:report);
    }
    misc_calls_and_exit();
    }

###################### Debian ###############################################
  buf = info_send_cmd(cmd: "cat /etc/debian_version");
  if ( buf && "/etc/debian_version" >!< buf ) set_kb_item(name: "Host/etc/debian-version", value: buf);

  if ( buf && egrep(string:buf, pattern:'^([0-9.]+|testing/unstable|lenny/sid)[ \t\r\n]*$'))
  {
    report += '\nThe remote Debian system is :\n' + buf;
    debrel = chomp(buf);
    if (debrel == "testing/unstable") might_be_ubuntu = 1;

    if ( debrel =~ "^[0-3]\." )
     buf = info_send_cmd(cmd:'COLUMNS=160 dpkg -l');
    else
     buf = info_send_cmd(cmd:'dpkg -l|cat');

    if (buf)
    {
  	buf2 =  info_send_cmd(cmd: 'cat /etc/lsb-release');
        if ("DISTRIB_ID=Ubuntu" >< buf2)
        {
          set_kb_item(name: "Host/Ubuntu", value: TRUE);
          report += '\nThis is a Ubuntu system\n';
          debrel = NULL;
          x = egrep(string: buf2, pattern: "DISTRIB_RELEASE=");
          if (x) v = split(x, sep: '='); 
          if (x && max_index(v) > 0)
           set_kb_item(name: "Host/Ubuntu/release", value: v[1]);
         }
      report += '\nLocal security checks have been enabled for this host.';
      set_kb_item(name:"Host/Debian/dpkg-l", value:buf);
      set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
      security_note(port:0, data:report);
    }
    else
    {
      report += 
'For any reason, dpkg did not produce any results, therefore local security 
checks have been disabled.';
    security_note(port:0, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'dpkg' did not return any result");
    }
    if (debrel)
     set_kb_item(name:"Host/Debian/release", value: debrel);

   misc_calls_and_exit();
  }

###################### Slackware ########################################

  buf = info_send_cmd(cmd: 'cat /etc/slackware-version');
  if (buf && "/etc/slackware-version" >!< buf) set_kb_item(name: "Host/etc/slackware-version", value: buf);

  if ("Slackware" >< buf)
  {
    buf = ereg_replace(string: buf, pattern: "^Slackware +", replace: "");
    report += '\nThe remote Slackware system is :\n' + buf;
    if (buf !~ '^[0-9.]+[ \t\r\n]*$')
    {
      report += '\nThe Slackware version is unknown, therefore 
local security checks have been disabled.\n';
      security_note(port:0, data:report);
      exit(0);
    }
    set_kb_item(name:"Host/Slackware/release", value: chomp(buf));

    buf = info_send_cmd(cmd: 'ls -1 /var/log/packages');

    if (buf)
    {
      report += '\nLocal security checks have been enabled for this host.';
      set_kb_item(name:"Host/Slackware/packages", value:buf);
      set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
      security_note(port:0, data:report);
    }
    else
    {
      report += 
'For some reason, /var/log/packages/ could not be read, therefore local
security checks have been disabled.';
    set_kb_item(name:'HostLevelChecks/failure', value:"'/var/log/packages' could not be read");
    security_note(port:0, data:report);
    }
    misc_calls_and_exit();
  }

  # We do not support TurboLinux but we can check oboslete versions
  buf = info_send_cmd(cmd: "cat /etc/turbolinux-release");
  if (buf && "/etc/turbolinux-release" >!< buf ) set_kb_item(name: "Host/etc/turbolinux-release", value: buf);

  report += 
'\nThe remote Linux distribution is not supported, therefore local security checks have not been enabled.';
  security_note(port:0, data:report);
  set_kb_item(name:'HostLevelChecks/failure', value:"Unsupported Linux distribution");
  misc_calls_and_exit();
}
######################## MacOS X ###########################################
else if ("Darwin" >< buf )
 {
  operating_system = info_send_cmd(cmd:'cat /System/Library/CoreServices/SystemVersion.plist');
  lines = split(operating_system, keep:FALSE);
  for ( i = 0 ; i < max_index(lines) ; i ++ )
  {
   if ( lines[i] =~ "<key>ProductVersion</key>")
	{
	operating_system = lines[i+1];
	break;
	}
  } 
  if ( operating_system =~ "<string>[0-9.]+</string>" )
  {
   operating_system = ereg_replace(pattern:".*<string>([0-9.]+)</string>.*", string:chomp(operating_system), replace:"\1");
   version = "Mac OS X " + operating_system;
  }
  else
  {
  operating_system = ereg_replace(pattern:"^.*Darwin Kernel Version ([0-9]+\.[0-9]+\.[0-9]+):.*$", string:buf, replace:"\1");
  num = split(operating_system, sep:".", keep:FALSE);
  version = "Mac OS X 10." + string(int(num[0]) - 4) + "." + int(num[1]);
  }


  buf = info_send_cmd(cmd: 'cat /private/etc/sysctl-macosxserver.conf');

  if ( "# /etc/sysctl-macosxserver.conf is reserved " >< buf  ) version = version + " Server";
  set_kb_item(name:"Host/MacOSX/Version", value:version);

  if ( operating_system =~ "^1[0-9]\." )
  {
	buf = info_send_cmd(cmd:'grep -A 1 displayName /Library/Receipts/InstallHistory.plist 2>/dev/null| grep string | sed \'s/<string>\\(.*\\)<\\/string>.*/\\1/g\' | sed \'s/^[	 ]*//g\'|tr  -d -c \'a-zA-Z0-9\\n _-\'|sort|uniq');
	buf += info_send_cmd(cmd: 'ls -1 /Library/Receipts|grep -v InstallHistory.plist');
  }
   else
	buf = info_send_cmd(cmd: 'ls -1 /Library/Receipts');

  if ( ! buf )
  {
   report += 
'\nIt was not possible to get the list of installed packages on the
remote Mac OS X system, therefore local security checks have been
disabled.';
   security_note(port:0, data:report);
   set_kb_item(name:'HostLevelChecks/failure', value:"Could not obtain the list of installed packages");
   exit(0);
  }
  set_kb_item(name:"Host/MacOSX/packages", value:buf);

  buf = info_send_cmd(cmd: 'ls -1 /Library/Receipts/boms /private/var/db/receipts/*.bom 2>/dev/null');
  if ( buf ) set_kb_item(name:"Host/MacOSX/packages/boms", value:buf);

  report += '\nLocal security checks have been enabled for this host.';
  set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
  security_note(port:0, data:report);
  misc_calls_and_exit();
 }
######################## Solaris ###########################################
else if ( egrep(pattern:"SunOS.*", string:buf) )
{
 buf = info_send_cmd(cmd: '/usr/bin/showrev -a');
 if ( ! buf || !egrep(pattern:"^Patch:", string:buf) ) buf = info_send_cmd(cmd:'/usr/sbin/patchadd -p');
 if ( ! buf )
 {
  report += 
'\nIt was not possible to gather the list of installed packages on the
remote Solaris system, therefore local security checks have been disabled.';
  security_note(port:0, data:report);
  set_kb_item(name:'HostLevelChecks/failure', value:"'showrev -a' and 'patchadd -p' both failed");
  exit(0);
 }

 set_kb_item(name:"Host/Solaris/showrev", value:buf);

 buf = egrep(pattern:"^Release: ", string:buf);
 buf -= "Release: ";
 set_kb_item(name:"Host/Solaris/Version", value:buf);

 buf = info_send_cmd(cmd: '/usr/bin/pkginfo -x | awk \'{ if ( NR % 2 ) { prev = $1 } else  { print prev" "$0  } }\'');


 if ( ! buf ) {
report = '\nIt was not possible to gather the list of installed packages on the
remote Solaris system, therefore local security checks have been disabled.';
  security_note(port:0, data:report);
  set_kb_item(name:'HostLevelChecks/failure', value:"'pkginfo' failed");
  exit(0);
 }


 array = split(buf, sep:'\n', keep:FALSE);
 foreach line ( array )
 {
  pkg = ereg_replace(pattern:"^([^ 	]*).*", replace:"\1", string:line);
  version = ereg_replace(pattern:"^" + pkg + " *\([^)]*\) (.*)", replace:"\1", string:line);
  set_kb_item(name:"Solaris/Packages/Versions/" + pkg, value:version);
 }

  set_kb_item(name:"Host/Solaris/pkginfo", value:buf);
  report += '\nLocal security checks have been enabled for this host.';
  set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
  security_note(port:0, data:report);
  misc_calls_and_exit();
}
############################# AIX ##############################################
else if ( "AIX" >< buf )
{
  release = ereg_replace(pattern:".*AIX[ ]+.*[ ]+([0-9]+[ ]+[0-9]+)[ ]+.*", replace:"\1", string:buf);
  items = split(release, sep:" ", keep:0);
  release = "AIX-" + items[1] + "." + items[0];
  set_kb_item(name:"Host/AIX/version", value:release); 

  buf = info_send_cmd(cmd: "oslevel -r");

  if ( buf )  set_kb_item(name:"Host/AIX/oslevel", value:buf);

  buf = info_send_cmd(cmd: "lslpp -Lc");

  if ( ! buf ) {
    report += 
'\nThe command "lslpp -Lc" did not return any results, therefore
AIX local security checks have not been enabled for
this test.';
    security_note(port:0, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'lslpp -Lc' failed");
    exit(0);
  }
  set_kb_item(name:"Host/AIX/lslpp", value:buf);
  report += '\nLocal security checks have been enabled for this host.';
  set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
  security_note(port:0, data:report);
  misc_calls_and_exit();
}
############################# HP-UX ##############################################
else if ( "HP-UX" >< buf )
{
  release = ereg_replace(pattern:".*HP-UX[ ]+.*[ ]+B\.([0-9]+\.+[0-9]+)[ ]+.*", replace:"\1", string:buf);
  set_kb_item(name:"Host/HP-UX/version", value:release); 

  if ("ia64" >< buf)
    hardware = ereg_replace(pattern:".*HP-UX[ ]+.*[ ]+B\.[0-9]+\.+[0-9]+[ ]+.[ ]+ia64.*", replace:"800", string:buf);
  else
    hardware = ereg_replace(pattern:".*HP-UX[ ]+.*[ ]+B\.[0-9]+\.+[0-9]+[ ]+.[ ]+[0-9]+/(7|8)[0-9]+.*", replace:"\100", string:buf);
  set_kb_item(name:"Host/HP-UX/hardware", value:hardware); 
  buf = info_send_cmd(cmd:"/usr/sbin/swlist -l fileset -a revision");
  if ( !buf )  {
    report += 
'\nThe command "swlist -l fileset -a revision" did not return any results,
therefore HP-UX local security checks have not been enabled for
this test.';
    security_note(port:0, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'swlist -l fileset -a revision' failed");
    exit(0);
  }

  set_kb_item(name:"Host/HP-UX/swlist", value:buf);
  report += '\nLocal security checks have been enabled for this host.';
  set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
  security_note(port:0, data:report);
  misc_calls_and_exit();
}
