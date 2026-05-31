import PageHeader from '@/components/layout/PageHeader'

export default function Dashboard() {
  return (
    <>
      <PageHeader
        title="Dashboard"
        description="System overview and recent activity."
      />
      <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
        Dashboard — coming in next step.
      </div>
    </>
  )
}
