package web

import (
	"html/template"

	"knotwork/internal/domain"
)

type repoEntry struct {
	Path        string
	Description string
	Private     bool
}

// page is the single view model shared by every HTML template.
type page struct {
	Title  string
	Page   string
	Authed bool
	User   domain.User

	Repo       domain.Repository
	Role       string
	CanWrite   bool
	CloneURL   string
	DefaultRef string
	TreeURL    string
	IsEmpty    bool

	Repos     []repoEntry
	MergeReqs []domain.MergeRequest
	Pipelines []domain.Pipeline
	MR        domain.MergeRequest
	Pipeline  domain.Pipeline

	Error string
}

const baseLayout = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<link rel="stylesheet" href="/static/app.css">
<script type="module" src="/static/app.js"></script>
</head>
<body data-page="{{.Page}}">
<header class="container site-header">
<nav>
<a href="/" class="brand">Knotwork</a>
<span class="spacer"></span>
{{if .Authed}}
<a href="/repos/new" class="new-repo-link" role="button">+ New</a>
<span class="meta">{{.User.Username}}{{if .User.IsAdmin}} · admin{{end}}</span>
<form method="POST" action="/auth/logout" class="logout-form">
<button type="submit" class="link-button">Sign out</button>
</form>
{{else}}
<a href="/auth/login">Sign in</a>
{{end}}
</nav>
</header>
<main class="container">
{{template "content" .}}
</main>
<footer class="container meta site-footer">Knotwork 0.1.0 · single-node, federated Git collaboration</footer>
</body>
</html>`

const homeContent = `{{define "content"}}
<section class="hero">
<h1>Knotwork</h1>
<p class="lead">Self-hosted Git collaboration with OIDC sign-in, merge requests, embedded CI, and opt-in federation.</p>
{{if not .Authed}}<p><a href="/auth/login" role="button">Sign in with OIDC</a></p>{{end}}
</section>

<section>
<div class="repo-section-header">
<h2>Repositories</h2>
{{if .Authed}}<a href="/repos/new" role="button">+ New repository</a>{{end}}
</div>
{{if .Repos}}
<div class="repo-grid">
{{range .Repos}}
<article class="card">
<h3><a href="/repos/{{.Path}}">{{.Path}}</a></h3>
{{if .Private}}<span class="badge">private</span>{{else}}<span class="badge">public</span>{{end}}
{{if .Description}}<p class="meta">{{.Description}}</p>{{end}}
</article>
{{end}}
</div>
{{else}}
<p class="meta">No visible repositories yet.{{if .Authed}} <a href="/repos/new">Create one now</a>.{{else}} Sign in to create one.{{end}}</p>
{{end}}
</section>
{{end}}`

const newRepoContent = `{{define "content"}}
<nav class="breadcrumb"><a href="/">Repositories</a> / <span>New</span></nav>

<h1>Create a new repository</h1>
<p class="meta lead">A repository contains all project files, revision history, merge requests, and pipelines.</p>

<form id="new-repo-form" class="new-repo-form" method="POST" action="/repos/new">
  {{if .Error}}
  <div class="error" role="alert">{{.Error}}</div>
  {{end}}
  <div id="new-repo-error" class="error" style="display:none;" role="alert"></div>

  <div class="form-group">
    <label for="repo-name">Repository name <span class="required">*</span></label>
    <div class="repo-name-input-group">
      <span class="owner-prefix">{{.User.Username}} /</span>
      <input type="text" id="repo-name" name="name" required pattern="[A-Za-z0-9][A-Za-z0-9._-]*" placeholder="my-awesome-project" autocomplete="off" autofocus>
    </div>
    <p class="field-hint">Must start with a letter or digit, up to 100 characters ([A-Za-z0-9._-]).</p>
  </div>

  <div class="form-group">
    <label for="repo-description">Description <span class="meta">(optional)</span></label>
    <input type="text" id="repo-description" name="description" placeholder="Short description of your project">
  </div>

  <div class="form-group">
    <span class="form-label">Visibility</span>
    <div class="visibility-options">
      <label class="visibility-option">
        <input type="radio" name="visibility" value="private" checked>
        <div class="visibility-text">
          <strong>Private</strong>
          <span class="meta">Only you and collaborators can view and clone this repository.</span>
        </div>
      </label>
      <label class="visibility-option">
        <input type="radio" name="visibility" value="public">
        <div class="visibility-text">
          <strong>Public</strong>
          <span class="meta">Anyone on the instance or internet can view this repository.</span>
        </div>
      </label>
    </div>
  </div>

  <div class="form-actions">
    <button type="submit" id="create-repo-btn">Create repository</button>
    <a href="/" role="button" class="secondary">Cancel</a>
  </div>
</form>
{{end}}`

const repoContent = `{{define "content"}}
<nav class="breadcrumb"><a href="/">Repositories</a> / <span>{{.Repo.Path}}</span></nav>

<header class="repo-header">
<div>
<h1>{{.Repo.Path}}</h1>
<p class="meta">
{{if .Repo.IsPrivate}}<span class="badge">private</span>{{else}}<span class="badge">public</span>{{end}}
{{if .Role}} · your role: {{.Role}}{{end}}
</p>
</div>
{{if and .CanWrite (not .IsEmpty)}}
<a href="/repos/{{.Repo.Path}}/merge-requests/new" role="button">New MR</a>
{{end}}
</header>

<details class="clone">
<summary>Clone URL</summary>
<pre><code>git clone {{.CloneURL}}</code></pre>
</details>

{{if .IsEmpty}}
<div class="empty-repo card">
<h2>Get started with this repository</h2>
<p class="meta">This repository is empty. Push commits to branch <code>{{.DefaultRef}}</code> to get started.</p>

<section class="instructions-section">
<h3>First time using Knotwork Git?</h3>
<p class="meta">Authorize your Git client with Knotwork CLI:</p>
<pre><code>knotwork auth login</code></pre>
</section>

<section class="instructions-section">
<h3>Create a new repository on the command line</h3>
<pre><code>mkdir {{.Repo.Name}}
cd {{.Repo.Name}}
git init -b {{.DefaultRef}}
echo "# {{.Repo.Name}}" >> README.md
git add README.md
git commit -m "first commit"
git remote add origin {{.CloneURL}}
git push -u origin {{.DefaultRef}}</code></pre>
</section>

<section class="instructions-section">
<h3>Push an existing repository from the command line</h3>
<pre><code>git remote add origin {{.CloneURL}}
git branch -M {{.DefaultRef}}
git push -u origin {{.DefaultRef}}</code></pre>
</section>
</div>
{{else}}
<div class="repo-browser">
<div class="tree-pane">
<h2 class="pane-title">Files · {{.DefaultRef}}</h2>
<div id="file-tree" data-repo="{{.Repo.Path}}" data-ref="{{.DefaultRef}}">
<p class="meta">Loading file tree…</p>
</div>
</div>
<div class="file-pane">
<div id="file-view">
<p class="meta">Select a file from the tree to view its contents.</p>
</div>
</div>
</div>
{{end}}

<div class="columns">
<section>
<h2>Merge requests</h2>
{{if .MergeReqs}}
<ul class="item-list">
{{range .MergeReqs}}
<li>
<a href="/repos/{{$.Repo.Path}}/merge-requests/{{.Number}}">#{{.Number}} {{.Title}}</a>
<span class="meta">{{.State}} · {{.SourceBranch}} → {{.TargetBranch}}</span>
</li>
{{end}}
</ul>
{{else}}
<p class="meta">No open merge requests.</p>
{{end}}
</section>

<section>
<h2>Pipelines</h2>
{{if .Pipelines}}
<ul class="item-list">
{{range .Pipelines}}
<li>
<a href="/repos/{{$.Repo.Path}}/pipelines/{{.ID}}">{{shortSHA .CommitSHA}}</a>
<span class="meta">{{.Status}} · {{.RefName}}</span>
</li>
{{end}}
</ul>
{{else}}
<p class="meta">No pipelines have run yet.</p>
{{end}}
</section>
</div>
{{end}}`

const mrContent = `{{define "content"}}
<nav class="breadcrumb"><a href="/">Repositories</a> / <a href="/repos/{{.Repo.Path}}">{{.Repo.Path}}</a> / <span>merge requests</span></nav>

<header>
<h1>#{{.MR.Number}} {{.MR.Title}}</h1>
<p class="meta">
{{.MR.State}} · {{.MR.SourceBranch}} → {{.MR.TargetBranch}}
{{if .MR.IsFederated}}<span class="badge">federated · {{.MR.OriginDomain}}</span>{{end}}
</p>
</header>

{{if .MR.Description}}<article class="card"><p>{{.MR.Description}}</p></article>{{end}}

<section>
<h2>Changes</h2>
<div id="diff-view" data-repo="{{.Repo.Path}}" data-number="{{.MR.Number}}">
<p class="meta">Loading diff…</p>
</div>
</section>
{{end}}`

const pipelineContent = `{{define "content"}}
<nav class="breadcrumb"><a href="/">Repositories</a> / <a href="/repos/{{.Repo.Path}}">{{.Repo.Path}}</a> / <span>pipeline</span></nav>

<header>
<h1>Pipeline {{shortSHA .Pipeline.CommitSHA}}</h1>
<p class="meta">
Status: <strong id="pipeline-status">{{.Pipeline.Status}}</strong>
· ref {{.Pipeline.RefName}}
{{if .Pipeline.RequiresApproval}}<span class="badge">approval required</span>{{end}}
</p>
</header>

{{if and .Pipeline.RequiresApproval .CanWrite}}
<p><button id="approve-pipeline" data-pipeline="{{.Pipeline.ID}}" data-repo="{{.Repo.Path}}">Approve and run pipeline</button></p>
{{end}}

<pre id="pipeline-log" class="log" data-pipeline="{{.Pipeline.ID}}"></pre>
{{end}}`

func newPage(content string) *template.Template {
	return template.Must(template.New("layout").Funcs(template.FuncMap{
		"shortSHA": func(sha string) string {
			if len(sha) > 8 {
				return sha[:8]
			}
			if sha == "" {
				return "unknown"
			}
			return sha
		},
	}).Parse(baseLayout + content))
}

var (
	homeTemplate     = newPage(homeContent)
	newRepoTemplate  = newPage(newRepoContent)
	repoPageTemplate = newPage(repoContent)
	mrPageTemplate   = newPage(mrContent)
	pipePageTemplate = newPage(pipelineContent)
)
