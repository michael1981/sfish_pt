#TRUSTED 04192e887eaa91b731bfa00f8e464ec66bdeb195c73fdf781e2831b3bf9eb2f3d4cbd0a673bc662b38cfbd60cf7322579275583b29da004f9b00ef68206309a4485193b1a62b3d06e53f63ea50b227f3853d6fc276ffda02adc28f83a1e77e185362b09e622a447006e448053d0d946460f3a47104744342b5d4680d9339cd683d61da53a45370bfa65b3711a0e7a3d1c3a3cc2e5a427a6c98658eabc45f9e19ce49fdb12dac534f29c394afb2db4b1b856b0592921d7347b6c910e837449b0e561ef254b07e674e13bea0d1a0b44e20b80b3144c7d43ee37e40720837137ce83dd4518987373175c461de208234c8aff06637197065f27c476e04cc3e411e79d6f8bdde3a24c0bb27e4a635c38150da710a55e371fb4972c92995fbf778a4ee29df31deb50a12d488e3f72e5799e77d0e6ea41b2166b9b0afe1dd0806950c88f0d4e63f9637e142ec115d95e60ffca54be1c7a283a699900190354fc66e0861b05f24d06308b6bc47b270b1c85aad5fd946937b5cee4f75deb374d396e9f008d96e6132ec982903cbad506519812574f73d345d331bb559bb3090860690e763ca05d1fd4050699c0282c0bf0ae290cfc36597f2aa181935a1235fb8a78a5fae9e668ed55a877e6f4a478c5513cb72c50b56469985c42b76dad8462edb41386f56de2567bf484e402c9754042326c5a968339b11ad2087c4b8f87ff5b0bfbc67
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34098);
 script_version ("1.3");
 script_name(english: "BIOS version (SSH)");
 
 script_set_attribute(attribute:"synopsis", value:
"The BIOS version could be read." );
 script_set_attribute(attribute:"description", value:
"Using the SMBIOS (aka DMI) interface, it was possible to get the BIOS
vendor and version." );
 script_set_attribute(attribute:"solution", value:"N/A");
 script_set_attribute(attribute:"risk_factor", value:
"None" );
script_end_attributes();

 
 script_summary(english: "Run dmidecode");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english: "General");

 script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl");
 script_require_ports("Services/ssh", 22);
 script_exclude_keys("BIOS/Vendor", "BIOS/Version", "BIOS/ReleaseDate");
 exit(0);
}


include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if (get_kb_item("BIOS/Vendor") && get_kb_item("BIOS/Version") && get_kb_item("BIOS/ReleaseDate")) exit(0);

# We may support other protocols here
if ( islocalhost() )
{
 if ( ! defined_func("pread") ) exit(0);
 info_t = INFO_LOCAL;
}
else
{
 sock_g = ssh_open_connection();
 if (! sock_g) exit(0);
 info_t = INFO_SSH;
}

# I planned initialy to run 
#  dmidecode -s bios-vendor 
#  dmidecode -s bios-version 
#  dmidecode -s bios-release-date
# Unfortunately, not all versions of dmidecode support the "-s" option.
# dmidecode -t 0 (which gives only BIOS information) is not supported
# everywhere either. So we have to parse the whole output.

# Work around broken $PATH
dirs = make_list( "", "/usr/sbin/", "/usr/local/sbin/", "/sbin/");

keys = make_list("Vendor", "Version", "Release Date");
values = make_list();
found = 0;

foreach d (dirs)
{
 cmd = strcat('LC_ALL=C ', d, 'dmidecode');
 buf = info_send_cmd(cmd: cmd);
 if ('BIOS Information' >< buf)
 {
   lines = split(buf, keep: 0);
   drop_flag = 1;
   foreach l (lines)
   {
     if (ereg(string: l, pattern: '^BIOS Information'))
     {
      drop_flag = 0;
      continue;
     }
     else if (ereg(string: l, pattern: '^[A-Z]')) drop_flag = 1; 
     if (drop_flag) continue;

     foreach k (keys)
     {
       pat = strcat('^[ \t]+', k, '[ \t]*:[  \t]*([^ \t].*)');
       v = eregmatch(string: l, pattern: pat);
       if (! isnull(v)) { values[k] = v[1]; found ++; }
     }
   } 
 }
 if (found > 0) break;
}

if (found || 'BIOS Information' >< buf || 'System Information' >< buf)
  set_kb_item(name: 'Host/dmidecode', value: buf);

if (! found) exit(0);

report = "";
foreach k (keys(values))
{
 k2 = str_replace(string: k, find: " ", replace: "");
 set_kb_item(name: strcat("BIOS/", k2), value: values[k]);
 report = strcat( report, k, 
 	  	  crap(data: ' ', length: 12 - strlen(k)), ' : ', values[k], '\n');
}

security_note(port: 0, extra: report);
