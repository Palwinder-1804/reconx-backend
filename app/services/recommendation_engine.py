def generate_recommendations(
    vulnerabilities
):

    recommendations = []

    for vuln in vulnerabilities:

        title = vuln.get(
            "title",
            ""
        )

        # ==========================
        # Dangerous Permissions
        # ==========================

        if title == (
            "Dangerous Permission"
        ):

            recommendations.append(

                "Remove unnecessary Android permissions and follow the principle of least privilege."
            )

        # ==========================
        # Debuggable App
        # ==========================

        elif title == (
            "Debuggable Application"
        ):

            recommendations.append(

                "Disable android:debuggable in production builds."
            )

        # ==========================
        # Backup Enabled
        # ==========================

        elif title == (
            "Backup Enabled"
        ):

            recommendations.append(

                "Disable application backups unless explicitly required."
            )

        # ==========================
        # Cleartext Traffic
        # ==========================

        elif title == (
            "Cleartext Traffic Enabled"
        ):

            recommendations.append(

                "Disable cleartext traffic and enforce HTTPS communication."
            )

        # ==========================
        # HTTP URL
        # ==========================

        elif title == (
            "Insecure HTTP URL"
        ):

            recommendations.append(

                "Replace insecure HTTP endpoints with HTTPS."
            )

        # ==========================
        # Hardcoded Secret
        # ==========================

        elif title == (
            "Hardcoded Secret"
        ):

            recommendations.append(

                "Move secrets and API keys to secure encrypted storage."
            )

        # ==========================
        # Weak Cryptography
        # ==========================

        elif title == (
            "Weak Cryptography"
        ):

            recommendations.append(

                "Replace weak cryptographic algorithms with modern secure standards."
            )

        # ==========================
        # Firebase
        # ==========================

        elif title == (
            "Firebase URL Found"
        ):

            recommendations.append(

                "Review Firebase configuration and apply proper access control rules."
            )

    # ==========================
    # Remove Duplicates
    # ==========================

    recommendations = list(
        set(recommendations)
    )

    # ==========================
    # Return Recommendations
    # ==========================

    return recommendations