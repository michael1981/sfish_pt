# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-16.xml
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
 script_id(28199);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200711-16");
 script_cve_id("CVE-2007-4351");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-16
(CUPS: Memory corruption)


    Alin Rad Pop (Secunia Research) discovered an off-by-one error in the
    ippReadIO() function when handling Internet Printing Protocol (IPP)
    tags that might allow to overwrite one byte on the stack.
  
Impact

    A local attacker could send a specially crafted IPP request containing
    "textWithLanguage" or "nameWithLanguage" tags, leading to a Denial of
    Service or the execution of arbitrary code with the privileges of the
    "lp" user. If CUPS is configured to allow network printing, this
    vulnerability might be remotely exploitable.
  
Workaround

    To avoid remote exploitation, network access to CUPS servers on port
    631/udp should be restricted. In order to do this, update the "Listen"
    setting in cupsd.conf to "Listen localhost:631" or add a rule to
    the system\'s firewall. However, this will not avoid local users from
    exploiting this vulnerability.
  
');
script_set_attribute(attribute:'solution', value: '
    All CUPS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-print/cups-1.2.12-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4351');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-16] CUPS: Memory corruption');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CUPS: Memory corruption');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-print/cups", unaffected: make_list("ge 1.2.12-r2"), vulnerable: make_list("lt 1.2.12-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
