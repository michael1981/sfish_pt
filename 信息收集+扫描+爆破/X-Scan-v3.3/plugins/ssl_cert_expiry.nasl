#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if ( ! defined_func("localtime") ) exit(0);

# How far (in days) to warn of certificate expiry. [Hmmm, how often
# will scans be run and how quickly can people obtain new certs???]
lookahead = 60;


if (description) {
  script_id(15901);
  script_version ("$Revision: 1.19 $"); 

  script_name(english:"SSL Certificate Expiry");
  script_summary(english:"Checks SSL certificate expiry");

  desc["english"] = "Synopsis :

The remote server's SSL certificate has already expired or will expire
shortly. 

Description :

This script checks expiry dates of certificates associated with SSL-
enabled services on the target and reports whether any have already
expired or will expire shortly. 

Solution :

Purchase or generate a new SSL certificate to replace the existing
one. 

Risk factor :

None";
  script_description(english:desc["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2004-2009 George A. Theall");

  script_dependencies("find_service1.nasl");
  if (NASL_LEVEL >= 3000)
    script_dependencies(
      "acap_starttls.nasl",
      "ftp_starttls.nasl",
      "imap4_starttls.nasl",
      "ldap_starttls.nasl",
      "nntp_starttls.nasl",
      "pop3_starttls.nasl",
      "smtp_starttls.nasl",
      "xmpp_starttls.nasl"
    );

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");


# This function converts a date expressed as:
#   Year(4)|Month(2)|Day(2)|Hour(2)|Min(2)|Sec(2)
# and returns it in a more human-friendly format.
function x509time_to_gtime(x509time) {
  local_var gtime, i, mm, mon, mons, parts, year;
  mons = "JanFebMarAprMayJunJulAugSepOctNovDec";

  if (x509time && x509time =~ "^[0-9]{14}Z?$") {
    parts[0] = substr(x509time, 0, 3);
    for (i=1; i<= 6; ++i) {
      parts[i] = substr(x509time, 2+i*2, 2+i*2+1);
    }

    year = int(parts[0]);

    mm = int(parts[1]);
    if (mm >= 1 && mm <= 12) {
      --mm;
      mon = substr(mons, mm*3, mm*3+2);
    }
    else {
      mon = "unk";
    }
    parts[2] = ereg_replace(string:parts[2], pattern:"^0", replace:" ");

    gtime = string(
      mon, " ", 
      parts[2], " ", 
      parts[3], ":", parts[4], ":", parts[5], " ", 
      year, " GMT"
    );
  }
  return gtime;
}


if (COMMAND_LINE) {
  ports = make_list(443);
  # nb: so we lied...
  set_kb_item(name:"Transports/TCP/443", value:ENCAPS_TLSv1);
  debug_level = 1;
}
else {
  ports = get_kb_list("Transport/SSL");
  starttls_ports = get_kb_list("*/*/starttls");
  if (!isnull(starttls_ports)) {
    foreach key (keys(starttls_ports))
    {
      port = key - "/starttls";
      port = strstr(port, "/") - "/";
      if (int(port) < 1 || int(port) > 65535) continue;
      ports = add_port_in_list(list:ports, port:port);
    }
  }
}

foreach port (ports) {
  if (!get_port_state(port)) continue;

  cert = get_server_cert(port:port, encoding:"der");
  if (!isnull(cert)) {

    # nb: maybe someday I'll actually *parse* ASN.1.
    v = stridx(cert, raw_string(0x30, 0x1e, 0x17, 0x0d));
    if (v >= 0) {
      v += 4;
      valid_start = substr(cert, v, v+11);
      v += 15;
      valid_end = substr(cert, v, v+11);

      if (valid_start =~ "^[0-9]{12}$" && valid_end =~ "^[0-9]{12}$") {
        # nb: YY >= 50 => YYYY = 19YY per RFC 3280 (4.1.2.5.1)
        if (int(substr(valid_start, 0, 1)) >= 50) valid_start = "19" + valid_start;
        else valid_start = "20" + valid_start;

        if (int(substr(valid_end, 0, 1)) >= 50) valid_end = "19" + valid_end;
        else valid_end = "20" + valid_end;

        # Get dates, expressed in UTC, for checking certs.
        # - right now.
        tm = localtime(unixtime(), utc:TRUE);
        now = string(tm["year"]);
        foreach field (make_list("mon", "mday", "hour", "min", "sec")) {
          if (tm[field] < 10) now += "0"; 
          now += tm[field];
        }
        # - 'lookahead' days in the future.
        tm = localtime(unixtime() + lookahead*24*60*60, utc:TRUE);
        future = string(tm["year"]);
        foreach field (make_list("mon", "mday", "hour", "min", "sec")) {
          if (tm[field] < 10) future += "0"; 
          future += tm[field];
        }
        debug_print("now:    ", now, ".");
        debug_print("future: ", future, ".");

        valid_start_alt = x509time_to_gtime(x509time:valid_start);
        valid_end_alt = x509time_to_gtime(x509time:valid_end);
        debug_print("valid not before: ", valid_start_alt, " (", valid_start, "Z).");
        debug_print("valid not after:  ", valid_end_alt,   " (", valid_end, "Z).");

        debug_print("The SSL certificate on port ", port, " is valid between ", valid_start_alt, " and ", valid_end_alt, ".", level:1);

        if (valid_start > now) {
          security_note(
            extra:string("\nThe SSL certificate of the remote service is not valid before ", valid_start_alt, "!"),
            port:port
          );
        }
        else if (valid_end < now) {
          security_warning(
            extra:string("\nThe SSL certificate of the remote service expired ", valid_end_alt, "!"),
            port:port
          );
          set_kb_item(name:'Transport/SSL/'+port+'/expired_cert', value:TRUE);
        }
        else if (valid_end < future) {
          security_note(
            extra:string("\nThe SSL certificate of the remote service will expire within ", lookahead, " days, at ", valid_end_alt, "."),
            port:port
          );
        }
      }
    }
  }
}
