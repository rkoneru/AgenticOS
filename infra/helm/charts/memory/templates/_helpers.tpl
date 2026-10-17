{{- define "memory.fullname" -}}
{{- printf "%s-memory" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "memory.labels" -}}
app.kubernetes.io/name: memory
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: axis
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "memory.selectorLabels" -}}
app.kubernetes.io/name: memory
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "memory.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "memory.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "memory.secretName" -}}
{{- .Values.secret.existingSecret | default (printf "%s-secret" (include "memory.fullname" .)) -}}
{{- end -}}
