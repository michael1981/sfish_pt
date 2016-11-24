# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-03.xml
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
 script_id(31834);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200804-03");
 script_cve_id("CVE-2008-1483", "CVE-2008-1657");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-03
(OpenSSH: Privilege escalation)


    Two issues have been discovered in OpenSSH:
    Timo Juhani
    Lindfors discovered that OpenSSH sets the DISPLAY variable in SSH
    sessions using X11 forwarding even when it cannot bind the X11 server
    to a local port in all address families (CVE-2008-1483).
    OpenSSH will execute the contents of the ".ssh/rc" file even when
    the "ForceCommand" directive is enabled in the global sshd_config
    (CVE-2008-1657).
  
Impact

    A local attacker could exploit the first vulnerability to hijack
    forwarded X11 sessions of other users and possibly execute code with
    their privileges, disclose sensitive data or cause a Denial of Service,
    by binding a local X11 server to a port using only one address family.
    The second vulnerability might allow local attackers to bypass intended
    security restrictions and execute commands other than those specified
    by "ForceCommand" if they are able to write to their home directory.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenSSH users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/openssh-4.7_p1-r6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1483');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1657');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-03] OpenSSH: Privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSSH: Privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/openssh", unaffected: make_list("ge 4.7_p1-r6"), vulnerable: make_list("lt 4.7_p1-r6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
