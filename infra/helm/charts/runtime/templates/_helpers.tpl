{{- define "runtime.fullname" -}}
{{- printf "%s-runtime" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "runtime.labels" -}}
app.kubernetes.io/name: runtime
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: axis
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "runtime.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "runtime.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
