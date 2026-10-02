"use client";
import { useRouter } from "next/navigation";
import { PageHeader } from "@/components/common";
import { BlueprintEditor } from "@/components/blueprint-editor";
import { STARTER_ABL } from "@/lib/abl-starter";

export default function NewBlueprint() {
  const router = useRouter();
  return (
    <>
      <title>New blueprint - AXIS Console</title>
      <PageHeader
        title="New blueprint"
        description="Validated live with the ABL compiler and linter. Publishing creates an immutable version."
      />
      <BlueprintEditor
        initial={STARTER_ABL}
        onPublished={(n, v) =>
          router.push(`/blueprints/${encodeURIComponent(n)}/${encodeURIComponent(v)}`)
        }
      />
    </>
  );
}
