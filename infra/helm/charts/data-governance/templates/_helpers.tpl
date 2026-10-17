{{- define "data-governance.fullname" -}}
{{- printf "%s-data-governance" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "data-governance.labels" -}}
app.kubernetes.io/name: data-governance
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: axis
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "data-governance.selectorLabels" -}}
app.kubernetes.io/name: data-governance
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "data-governance.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "data-governance.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "data-governance.secretName" -}}
{{- .Values.secret.existingSecret | default (printf "%s-secret" (include "data-governance.fullname" .)) -}}
{{- end -}}
