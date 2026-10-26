#!/usr/bin/env bash
# The documentation on the gateway: the crassostrea-docs repository, built
# with MkDocs and served by nginx at https://<hostname>/docs/ to logged-in
# administrators only (auth_request to the web UI, auth.docs_access).
#
#   DOCS_ENABLED  y: build and serve the documentation
#   DOCS_SOURCE   the docs repository: a git URL or a directory; empty: the
#                 crassostrea-docs checkout next to this repository, or
#                 without one the project's repository (DOCS_DEFAULT_SOURCE)
#   DOCS_REF      branch or tag of a git URL (default: its default branch)
#
# A git URL is cloned to DOCS_CHECKOUT; update.sh and `system/docs.sh update`
# fetch new commits. configure.sh rebuilds the site only when the source
# changed (DOCS_STAMP holds a hash of it). The build disables the theme's
# Google Fonts and the repository link (which queries GitHub), so pages load
# nothing from elsewhere except Mermaid diagrams.
#
# Sourced by common.sh (configure.sh, update.sh, system/docs.sh).

DOCS_ROOT=/usr/local/share/crassostrea/docs
DOCS_VENV=${SF_LIB}/docs-venv
DOCS_CHECKOUT=${SF_STATE}/docs-src
DOCS_STAMP=.sf-docs-source
DOCS_DEFAULT_SOURCE=https://github.com/SnailShea/crassostrea-docs.git

docs_is_url() {
  [[ $1 == *://* || $1 == git@* ]]
}

# The repository the documentation comes from: DOCS_SOURCE, else the
# crassostrea-docs checkout next to this repository, else the project's
docs_source() {
  local sibling
  if [[ -n ${DOCS_SOURCE:-} ]]; then
    echo "${DOCS_SOURCE}"
    return 0
  fi
  sibling=$(dirname "${SF_SRC}")/crassostrea-docs
  if [[ -f ${sibling}/mkdocs.yml ]]; then
    echo "${sibling}"
  else
    echo "${DOCS_DEFAULT_SOURCE}"
  fi
}

# The directory the site is built from
docs_source_dir() {
  local source
  source=$(docs_source)
  if docs_is_url "${source}"; then
    p "${DOCS_CHECKOUT}"
  else
    echo "${source%/}"
  fi
}

# git as the owner of a checkout (git refuses repositories of other users)
_docs_git() {
  local dir=$1 owner
  shift
  owner=$(stat -c %U "${dir}")
  if [[ ${owner} == root || ${EUID} -ne 0 ]]; then
    git -C "${dir}" "$@"
  else
    runuser -u "${owner}" -- git -C "${dir}" "$@"
  fi
}

# docs_fetch [--update]: clone a git URL if it is not there yet; --update
# also fetches new commits (a local checkout is fast-forwarded)
docs_fetch() {
  local update=$1 source dir
  source=$(docs_source)
  dir=$(docs_source_dir)
  if docs_is_url "${source}"; then
    if [[ ! -d ${dir}/.git ]]; then
      dry && { log "Would clone the documentation from ${source}"; return 0; }
      log "Cloning the documentation from ${source}"
      rm -rf "${dir}"
      mkdir -p "$(dirname "${dir}")"
      git clone -q --depth 1 ${DOCS_REF:+--branch "${DOCS_REF}"} "${source}" "${dir}" \
        || { warn "Cannot clone ${source}"; return 1; }
    elif [[ ${update} == --update ]]; then
      dry && return 0
      log "Fetching the documentation from ${source}"
      git -C "${dir}" remote set-url origin "${source}"
      git -C "${dir}" fetch -q --depth 1 origin "${DOCS_REF:-HEAD}" && git -C "${dir}" reset -q --hard FETCH_HEAD \
        || { warn "Cannot fetch ${source}${DOCS_REF:+ (${DOCS_REF})}"; return 1; }
    fi
  elif [[ ${update} == --update && -n ${dir} && -d ${dir}/.git ]] && ! dry; then
    # a local checkout is built as it is when it cannot be updated: it was not
    # cloned from anywhere (no upstream), or has diverged
    if ! _docs_git "${dir}" rev-parse --abbrev-ref --symbolic-full-name '@{u}' > /dev/null 2>&1; then
      log "The documentation checkout ${dir} has no upstream branch: building it as it is"
    else
      log "Updating the documentation checkout ${dir} (fast-forward only)"
      _docs_git "${dir}" pull -q --ff-only || warn "Cannot fast-forward ${dir}, building it as it is"
    fi
  fi
  return 0
}

# A hash of what the site is built from
docs_fingerprint() {
  local dir=$1
  (cd "${dir}" && find docs mkdocs.yml requirements.txt -type f -print0 2> /dev/null | sort -z \
    | xargs -0 sha256sum) | sha256sum | cut -d' ' -f1
}

# docs_build [--force]: build the site into DOCS_ROOT if the source changed
docs_build() {
  local force=$1 src stamp site venv cfg public
  src=$(docs_source_dir)
  if [[ -z ${src} || ! -f ${src}/mkdocs.yml ]]; then
    warn "No documentation in $(docs_source): DOCS_SOURCE must be the crassostrea-docs repository (git URL or directory)"
    return 1
  fi
  stamp=$(docs_fingerprint "${src}")
  site=$(p "${DOCS_ROOT}")
  if [[ ${force} != --force && -f ${site}/${DOCS_STAMP} && $(cat "${site}/${DOCS_STAMP}") == "${stamp}" ]]; then
    log "Documentation is up to date (${src})"
    return 0
  fi
  dry && { log "Would build the documentation from ${src}"; return 0; }
  log "Building the documentation from ${src}"

  # MkDocs and its theme in their own virtualenv, as pinned by the docs repository
  venv=$(p "${DOCS_VENV}")
  if [[ ! -x ${venv}/bin/mkdocs ]] || ! cmp -s "${src}/requirements.txt" "${venv}/requirements.txt"; then
    python3 -m venv --clear "${venv}" && "${venv}/bin/pip" install -q --disable-pip-version-check \
      -r "${src}/requirements.txt" || { warn "Cannot install MkDocs (${src}/requirements.txt)"; return 1; }
    cp "${src}/requirements.txt" "${venv}/requirements.txt"
  fi

  public=${WEB_PUBLIC_URL:-https://${CRASSOSTREA_HOSTNAME}}
  cfg=$(mktemp -d) || return 1
  # no repository link: the theme would ask GitHub's API for its stars and forks
  cat > "${cfg}/mkdocs.yml" <<EOF
INHERIT: '${src}/mkdocs.yml'
docs_dir: '${src}/docs'
site_url: '${public%/}/docs/'
repo_url: null
edit_uri: null
theme:
  font: false
EOF
  rm -rf "${site}.new"
  mkdir -p "$(dirname "${site}")"
  if ! "${venv}/bin/mkdocs" build --quiet --clean -f "${cfg}/mkdocs.yml" --site-dir "${site}.new"; then
    rm -rf "${cfg}" "${site}.new"
    warn "Building the documentation failed; the previous site stays"
    return 1
  fi
  rm -rf "${cfg}"
  echo "${stamp}" > "${site}.new/${DOCS_STAMP}"
  chmod -R u=rwX,go=rX "${site}.new"
  if [[ ${EUID} -eq 0 ]] && command -v selinuxenabled > /dev/null && selinuxenabled; then
    semanage fcontext -a -t httpd_sys_content_t "${DOCS_ROOT}(\.new|\.old)?(/.*)?" 2> /dev/null \
      || semanage fcontext -m -t httpd_sys_content_t "${DOCS_ROOT}(\.new|\.old)?(/.*)?"
    restorecon -R "${site}.new" > /dev/null 2>&1
  fi
  rm -rf "${site}.old"
  [[ -d ${site} ]] && mv "${site}" "${site}.old"
  mv "${site}.new" "${site}" && rm -rf "${site}.old"
  restorecon -R "${site}" > /dev/null 2>&1
  log "Documentation built: ${public%/}/docs/"
}

# Remove the site, MkDocs and a cloned source
docs_remove() {
  local dir
  dir=$(p "${DOCS_ROOT}")
  [[ -e ${dir} || -e $(p "${DOCS_VENV}") || -e $(p "${DOCS_CHECKOUT}") ]] || return 0
  log "Removing the documentation from the gateway"
  rm -rf "${dir}" "${dir}.new" "${dir}.old" "$(p "${DOCS_VENV}")" "$(p "${DOCS_CHECKOUT}")"
}

# nginx locations of the HTTPS server (DOCS_ENABLED): the site for
# administrators; anyone else is sent to the login page
docs_nginx_locations() {
  is_yes "${DOCS_ENABLED:-n}" || return 0
  cat <<EOF

  # Documentation (system/lib/docs.sh): administrators only
  location = /docs {
    return 301 /docs/;
  }

  location ^~ /docs/ {
    auth_request /_sf_docs_auth;
    error_page 401 = @sf_docs_login;
    alias ${DOCS_ROOT}/;
    index index.html;
    # add_header here replaces the server's: HSTS again
    add_header Strict-Transport-Security "max-age=15768000" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy same-origin always;
  }

  location = /_sf_docs_auth {
    internal;
    proxy_pass http://127.0.0.1:8000/auth/docs;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$remote_addr;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Forwarded-Host \$host;
  }

  location @sf_docs_login {
    return 302 /login?next=\$uri;
  }
EOF
}
