{{- define "marketplace.fullname" -}}
{{- printf "%s-marketplace" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "marketplace.labels" -}}
app.kubernetes.io/name: marketplace
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: axis
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "marketplace.selectorLabels" -}}
app.kubernetes.io/name: marketplace
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "marketplace.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "marketplace.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "marketplace.secretName" -}}
{{- .Values.secret.existingSecret | default (printf "%s-secret" (include "marketplace.fullname" .)) -}}
{{- end -}}
