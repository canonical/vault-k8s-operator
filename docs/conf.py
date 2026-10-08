import datetime
import os

# Configuration for the Sphinx documentation builder.
# All configuration specific to your project should be done in this file.
#
# A complete list of built-in Sphinx configuration values:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
#
# The Sphinx Stack uses the Canonical Sphinx theme to keep all documentation consistent
# and on brand:
# https://github.com/canonical/canonical-sphinx

#######################
# Project information #
#######################

# Project name
project = "Vault Charms"

# Author name; used in the default copyright statement in the page footer
author = "Canonical Ltd."

# The year in the copyright statement
copyright = f"{datetime.date.today().year}"

# Sidebar documentation title
html_title = project + " documentation"

# Documentation website URL
# TODO: once the ubuntu.com/docs/vault-charms proxy is live, READTHEDOCS_CANONICAL_URL
# (set automatically by Read the Docs) will take precedence over this fallback.
ogp_site_url = os.environ.get("READTHEDOCS_CANONICAL_URL", "https://ubuntu.com/docs/vault-charms/")

# Preview name of the documentation website
ogp_site_name = project

# Preview image URL
ogp_image = "https://assets.ubuntu.com/v1/253da317-image-document-ubuntudocs.svg"

# Dictionary of values to pass into the Sphinx context for all pages:
# https://www.sphinx-doc.org/en/master/usage/configuration.html#confval-html_context
html_context = {
    # Product page URL; can be different from product docs URL
    "product_page": "github.com/canonical/vault-k8s-operator",
    # Your Mattermost channel URL
    "mattermost": "",
    # Your Matrix channel URL
    "matrix": "https://matrix.to/#/#tls:ubuntu.com",
    # Your documentation GitHub repository URL. If set, links for viewing the
    # documentation source files and creating GitHub issues are added at the bottom of
    # each page.
    "github_url": "https://github.com/canonical/vault-k8s-operator",
    # Docs branch in the repo; used in links for viewing the source files
    "repo_default_branch": "main",
    # Docs location in the repo; used in links for viewing the source files
    "repo_folder": "/docs/",
    # To enable listing contributors on individual pages, set to True
    "display_contributors": False,
    # Required for feedback button
    "github_issues": "enabled",
    # Passes the top-level 'author' value to the theme
    "author": author,
    # Documentation license information
    "license": {
        "name": "Apache-2.0",
        "url": "https://github.com/canonical/vault-k8s-operator/blob/main/LICENSE",
    },
}

# Enables the "Edit this page" / "Suggest an edit" link on pages
html_theme_options = {
    "source_edit_link": "https://github.com/canonical/vault-k8s-operator",
}

# Slug used to prefix 404 links once hosted behind the ubuntu.com/docs proxy
slug = "docs/vault-charms"

#######################
# Sitemap configuration: https://sphinx-sitemap.readthedocs.io/
#######################

# Use RTD canonical URL to ensure duplicate pages have a specific canonical URL
html_baseurl = os.environ.get("READTHEDOCS_CANONICAL_URL", "https://ubuntu.com/docs/vault-charms/")

# sphinx-sitemap uses html_baseurl to generate the full URL for each page:
sitemap_url_scheme = "{link}"

# Avoids clashing with the ubuntu.com root sitemap once proxied
sitemap_filename = "doc-sitemap.xml"

# Include `lastmod` dates in the sitemap:
sitemap_show_lastmod = True

################################
# Template and asset locations #
################################

html_static_path = ["_static"]

#############
# Redirects #
#############

# Add redirects to the 'redirects.txt' file
# https://sphinxext-rediraffe.readthedocs.io/en/latest/
rediraffe_redirects = "redirects.txt"

# Strips '/index.html' from destination URLs when building with 'dirhtml'
rediraffe_dir_only = True

###########################
# Link checker exceptions #
###########################

# A regex list of URLs that are ignored by 'make linkcheck'
linkcheck_ignore = [
    "http://127.0.0.1:8000",
    "https://developer.hashicorp.com/*",
    "https://github.com/canonical/ACME/*",
    r"https://matrix\.to/#/#tls:ubuntu\.com",
]

# A regex list of URLs where anchors are ignored by 'make linkcheck'
linkcheck_anchors_ignore_for_url = [r"https://github\.com/.*"]

# Give linkcheck multiple tries on failure
linkcheck_retries = 3

########################
# Configuration extras #
########################

# Adds custom CSS files, located under 'html_static_path'
html_css_files = [
    "https://assets.ubuntu.com/v1/d86746ef-cookie_banner.css",
]

# Adds custom JavaScript files, located under 'html_static_path'
html_js_files = [
    "js/overwrite_links.js",
    "https://assets.ubuntu.com/v1/287a5e8f-bundle.js",
]

# Custom Sphinx extensions; see
# https://www.sphinx-doc.org/en/master/usage/extensions/index.html
extensions = [
    "canonical_sphinx",
    "notfound.extension",
    "sphinx_design",
    "sphinx_rerediraffe",
    "sphinx_reredirects",
    "sphinx_tabs.tabs",
    "sphinxcontrib.jquery",
    "sphinxext.opengraph",
    "sphinx_related_links",
    "sphinx_roles",
    "sphinx_terminal",
    "sphinx_youtube_links",
    "sphinxcontrib.cairosvgconverter",
    "sphinx_last_updated_by_git",
    "sphinx_sitemap",
    "sphinx.ext.intersphinx",
]

# Excludes files or directories from processing
exclude_patterns = [
    "doc-cheat-sheet*",
    ".venv*",
    "_dev",
]

# Specifies a reST snippet to be prepended to each .rst file
# This defines a :center: role that centers table cell content.
# This defines a :h2: role that styles content for use with PDF generation.
rst_prolog = """
.. role:: center
   :class: align-center
.. role:: h2
    :class: hclass2
.. role:: woke-ignore
    :class: woke-ignore
.. role:: vale-ignore
    :class: vale-ignore
"""

# Configuration for Intersphinx mapping
intersphinx_mapping = {
    "starter-pack": (
        "https://canonical-example-product-documentation.readthedocs-hosted.com/en/latest",
        None,
    )
}

