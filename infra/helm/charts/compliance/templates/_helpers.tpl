{{- define "compliance.fullname" -}}
{{- printf "%s-compliance" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "compliance.labels" -}}
app.kubernetes.io/name: compliance
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: axis
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "compliance.selectorLabels" -}}
app.kubernetes.io/name: compliance
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "compliance.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "compliance.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "compliance.secretName" -}}
{{- .Values.secret.existingSecret | default (printf "%s-secret" (include "compliance.fullname" .)) -}}
{{- end -}}
