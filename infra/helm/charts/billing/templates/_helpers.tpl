{{- define "billing.fullname" -}}
{{- printf "%s-billing" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "billing.labels" -}}
app.kubernetes.io/name: billing
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: axis
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "billing.selectorLabels" -}}
app.kubernetes.io/name: billing
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "billing.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "billing.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "billing.secretName" -}}
{{- .Values.secret.existingSecret | default (printf "%s-secret" (include "billing.fullname" .)) -}}
{{- end -}}
