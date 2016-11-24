# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200610-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(22930);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200610-15");
 script_cve_id("CVE-2006-4345", "CVE-2006-4346", "CVE-2006-5444", "CVE-2006-5445");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200610-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200610-15
(Asterisk: Multiple vulnerabilities)


    Asterisk contains buffer overflows in channels/chan_mgcp.c from the
    MGCP driver and in channels/chan_skinny.c from the Skinny channel
    driver for Cisco SCCP phones. It also dangerously handles
    client-controlled variables to determine filenames in the Record()
    function. Finally, the SIP channel driver in channels/chan_sip.c could
    use more resources than necessary under unspecified circumstances.
  
Impact

    A remote attacker could execute arbitrary code by sending a crafted
    audit endpoint (AUEP) response, by sending an overly large Skinny
    packet even before authentication, or by making use of format strings
    specifiers through the client-controlled variables. An attacker could
    also cause a Denial of Service by resource consumption through the SIP
    channel driver.
  
Workaround

    There is no known workaround for the format strings vulnerability at
    this time. You can comment the lines in /etc/asterisk/mgcp.conf,
    /etc/asterisk/skinny.conf and /etc/asterisk/sip.conf to deactivate the
    three vulnerable channel drivers. Please note that the MGCP channel
    driver is disabled by default.
  
');
script_set_attribute(attribute:'solution', value: '
    All Asterisk users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/asterisk-1.2.13"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4345');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4346');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5444');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5445');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200610-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200610-15] Asterisk: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Asterisk: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/asterisk", unaffected: make_list("ge 1.2.13", "rge 1.0.12"), vulnerable: make_list("lt 1.2.13", "lt 1.0.12")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
