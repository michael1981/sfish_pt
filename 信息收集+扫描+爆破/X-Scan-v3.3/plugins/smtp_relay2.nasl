#
# (C) Tenable Network Security, Inc.
#

# References
# Date: Mon, 25 Aug 2003 05:38:53 -0700
# From: "st0ff st0ff" <if0ff@YAHOO.COM>
# Subject: Can NT4 SMTP Service be misused for mail spamming
# To: NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#
# Date:	 Fri, 19 Sep 2003 16:47:45 +0200
# De:	eric@LIEGE.COM
# Subject:	Re: Can NT4 SMTP Service be misused for mail spamming
# To:	NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#

include("compat.inc");

if(description)
{
 script_id(11852);
 script_version ("$Revision: 1.15 $");

 script_name(english:"MTA Open Mail Relaying Allowed (thorough test)");
 
script_set_attribute(attribute:"synopsis", value:
"An open SMTP relay is running on this port." );
 script_set_attribute(attribute:"description", value:
"The remote SMTP server is insufficiently protected against relaying. 
This means that it allows spammers to use your mail server to send 
their mails to the world, thus wasting your network bandwidth.");
 script_set_attribute(attribute:"solution", value:
"Reconfigure your SMTP server so that it cannot be used as a relay 
any more.");
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
  script_end_attributes();

 script_summary(english:"Tries misc invalid tricks to circumvent anti-relay functions"); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl",
	"smtp_relay.nasl", "smtp_settings.nasl");
 script_exclude_keys("SMTP/wrapped", "SMTP/qmail", "SMTP/spam");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#

include("global_settings.inc");
include("smtp_func.inc");
include("misc_func.inc");
include("network_func.inc");

# can't perform this test on localhost
if(islocalhost())exit(0);

if (is_private_addr()) exit(0);

port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);
if (! get_port_state(port)) exit(0);

# No use to try "advanced" tests if it is a wide open relay
if (get_kb_item("SMTP/" + port + "/spam")) exit(0);

domain = get_kb_item("Settings/third_party_domain");
if (! domain) domain = 'example.com';

soc = smtp_open(port: port, helo: NULL);
if (! soc) exit(0);
 
dest_name = get_host_name();
dest_ip = get_host_ip();
dest_name = get_host_name();
src_name = this_host_name();

t1 = strcat('nobody@', domain);
f1 = strcat('nessus@', dest_name);
f2 = strcat('nessus@[', dest_ip, ']');

i= 0;
from_l[i] = strcat("nobody@", domain);
to_l[i] = t1;
i ++;
from_l[i] = strcat("nessus@", rand_str(), ".", domain);
to_l[i] = t1;
i ++;
from_l[i] = "nessus@localhost";
to_l[i] = t1;
i ++;
from_l[i] = "nessus";
to_l[i] = t1;
i ++;
from_l[i] = "";
to_l[i] = t1;
i ++;
from_l[i] = "";
to_l[i] = t1;
i ++;
from_l[i] = strcat("nessus@", dest_name);
to_l[i] = t1;
i ++;
from_l[i] = strcat("nessus@[", dest_ip, "]");
to_l[i] = t1;
i ++;
from_l[i] = strcat("nessus@", dest_name);
to_l[i] = strcat("nobody%", domain, "@", dest_name);
i ++;
from_l[i] = strcat("nessus@", dest_name);
to_l[i] = strcat("nobody%", domain, "@[", dest_ip, "]");
i ++;
from_l[i] = strcat("nessus@", dest_name);
to_l[i] = strcat('nobody@', domain, '@', dest_name);
i ++;
from_l[i] = strcat("nessus@", dest_name);
to_l[i] = strcat('"nobody@', domain, '"@[', dest_ip, ']');
i ++;
from_l[i] = f1;
to_l[i] = strcat('nobody@', domain, '@[', dest_ip, ']');
i ++;
from_l[i] = f2;
to_l[i] = strcat('@', dest_name, ':nobody@', domain);
i ++;
from_l[i] = f1;
to_l[i] = strcat('@[', dest_ip, ']:nobody@', domain);
i ++;
from_l[i] = f1;
to_l[i] = strcat(domain, '!nobody@[', dest_ip, ']');
i ++;
from_l[i] = strcat('postmaster@', dest_name);
to_l[i] = t1;
i ++;

rep = '';
send(socket: soc, data: strcat('HELO ', src_name, '\r\n'));
smtp_recv_line(socket: soc);
for (i = 0; soc && (from_l[i] || to_l[i]); i ++)
{
  mf = strcat('MAIL FROM: <', from_l[i], '>\r\n');
  send(socket: soc, data: mf);
  l = smtp_recv_line(socket: soc);
  if (! l || l =~ '^5[0-9][0-9]')
  {
    smtp_close(socket: soc);
    soc = smtp_open(port: port, helo: domain);
  }
  else
  {
    rt = strcat('RCPT TO: <', to_l[i], '>\r\n');
    send(socket: soc, data: rt);
    l = smtp_recv_line(socket: soc);
    if (l =~ '^2[0-9][0-9]')
    {
      flag = 1;
      # Postfix may defer the error message until the DATA command.
      send(socket: soc, data: 'DATA\r\n');
      l = smtp_recv_line(socket: soc);
      if (l =~ '^3[0-9][0-9]')
      {
        flag = 1;
	# Violently close the socket so that we do not send an empty message
	close(soc); soc = NULL;
      }
      else
        flag = 0;

      if (flag)
      {
        mf -= '\r\n'; rt -= '\r\n';
        rep = strcat(rep, '\t', mf, '\n\t', rt, '\n\n');
        break;
      }
    }
    
    if (soc != NULL)
      smtp_close(socket: soc);
    soc = smtp_open(port: port, helo: NULL);
   }
}

if (rep)
{
  security_hole(port: port, extra: 
strcat('\nNessus was able to relay mails by sending those sequences :\n\n', rep));
  set_kb_item(name:"SMTP/" + port + "/spam", value:TRUE);
  set_kb_item(name:"SMTP/spam", value:TRUE);
}
