{{- define "risk-kernel.fullname" -}}
{{- printf "%s-risk-kernel" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "risk-kernel.labels" -}}
app.kubernetes.io/name: risk-kernel
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: axis
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "risk-kernel.selectorLabels" -}}
app.kubernetes.io/name: risk-kernel
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "risk-kernel.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "risk-kernel.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "risk-kernel.secretName" -}}
{{- .Values.secret.existingSecret | default (printf "%s-secret" (include "risk-kernel.fullname" .)) -}}
{{- end -}}
