{{- define "registry.fullname" -}}
{{- printf "%s-registry" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "registry.labels" -}}
app.kubernetes.io/name: registry
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: axis
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "registry.selectorLabels" -}}
app.kubernetes.io/name: registry
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "registry.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "registry.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "registry.secretName" -}}
{{- .Values.secret.existingSecret | default (printf "%s-secret" (include "registry.fullname" .)) -}}
{{- end -}}
