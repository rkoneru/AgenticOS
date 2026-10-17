{{- define "api-gateway.fullname" -}}
{{- printf "%s-api-gateway" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "api-gateway.labels" -}}
app.kubernetes.io/name: api-gateway
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: axis
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "api-gateway.selectorLabels" -}}
app.kubernetes.io/name: api-gateway
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "api-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "api-gateway.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "api-gateway.secretName" -}}
{{- .Values.secret.existingSecret | default (printf "%s-secret" (include "api-gateway.fullname" .)) -}}
{{- end -}}
