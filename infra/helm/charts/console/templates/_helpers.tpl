{{- define "console.fullname" -}}
{{- printf "%s-console" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "console.labels" -}}
app.kubernetes.io/name: console
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: axis
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "console.selectorLabels" -}}
app.kubernetes.io/name: console
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "console.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "console.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "console.secretName" -}}
{{- .Values.secret.existingSecret | default (printf "%s-secret" (include "console.fullname" .)) -}}
{{- end -}}
