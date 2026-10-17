{{- define "docs-site.fullname" -}}
{{- printf "%s-docs-site" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "docs-site.labels" -}}
app.kubernetes.io/name: docs-site
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: axis
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "docs-site.selectorLabels" -}}
app.kubernetes.io/name: docs-site
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "docs-site.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "docs-site.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
