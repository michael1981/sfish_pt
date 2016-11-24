# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-31.xml
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
 script_id(31671);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200803-31");
 script_cve_id("CVE-2007-5894", "CVE-2007-5971", "CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-31 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-31
(MIT Kerberos 5: Multiple vulnerabilities)


    Two vulnerabilities were found in the Kerberos 4 support in
    KDC: A global variable is not set for some incoming message types,
    leading to a NULL pointer dereference or a double free()
    (CVE-2008-0062) and unused portions of a buffer are not properly
    cleared when generating an error message, which results in stack
    content being contained in a reply (CVE-2008-0063).
    Jeff
    Altman (Secure Endpoints) discovered a buffer overflow in the RPC
    library server code, used in the kadmin server, caused when too many
    file descriptors are opened (CVE-2008-0947).
    Venustech AD-LAB
    discovered multiple vulnerabilities in the GSSAPI library: usage of a
    freed variable in the gss_indicate_mechs() function (CVE-2007-5901) and
    a double free() vulnerability in the gss_krb5int_make_seal_token_v3()
    function (CVE-2007-5971).
  
Impact

    The first two vulnerabilities can be exploited by a remote
    unauthenticated attacker to execute arbitrary code on the host running
    krb5kdc, compromise the Kerberos key database or cause a Denial of
    Service. These bugs can only be triggered when Kerberos 4 support is
    enabled.
    The RPC related vulnerability can be exploited by a remote
    unauthenticated attacker to crash kadmind, and theoretically execute
    arbitrary code with root privileges or cause database corruption. This
    bug can only be triggered in configurations that allow large numbers of
    open file descriptors in a process.
    The GSSAPI vulnerabilities could be exploited by a remote attacker to
    cause Denial of Service conditions or possibly execute arbitrary code.
  
Workaround

    Kerberos 4 support can be disabled via disabling the "krb4" USE flag
    and recompiling the ebuild, or setting "v4_mode=none" in the
    [kdcdefaults] section of /etc/krb5/kdc.conf. This will only work around
    the KDC related vulnerabilities.
  
');
script_set_attribute(attribute:'solution', value: '
    All MIT Kerberos 5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/mit-krb5-1.6.3-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5894');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5971');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0062');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0063');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0947');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-31.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-31] MIT Kerberos 5: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MIT Kerberos 5: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-crypt/mit-krb5", unaffected: make_list("ge 1.6.3-r1"), vulnerable: make_list("lt 1.6.3-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
