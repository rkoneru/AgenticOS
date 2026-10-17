{{- define "control-plane.fullname" -}}
{{- printf "%s-control-plane" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "control-plane.labels" -}}
app.kubernetes.io/name: control-plane
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: axis
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "control-plane.selectorLabels" -}}
app.kubernetes.io/name: control-plane
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "control-plane.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "control-plane.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "control-plane.secretName" -}}
{{- .Values.secret.existingSecret | default (printf "%s-secret" (include "control-plane.fullname" .)) -}}
{{- end -}}
