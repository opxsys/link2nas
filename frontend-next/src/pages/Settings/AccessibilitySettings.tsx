import SectionCard from '@/components/common/SectionCard'

export default function AccessibilitySettings() {
  return (
    <SectionCard
      title="Accessibility"
      description="Theme and accessibility preferences."
    >
      <div className="grid gap-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {['Light', 'Dark', 'High Contrast', 'Colorblind'].map((theme) => (
            <button
              key={theme}
              type="button"
              className="rounded-lg border border-border bg-background p-4 text-left shadow-sm transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <p className="text-sm font-semibold text-foreground">{theme}</p>
              <p className="mt-1 text-xs text-muted-foreground">Visual theme preview</p>
            </button>
          ))}
        </div>

        <div className="rounded-lg border border-border bg-background p-4">
          <p className="text-sm font-semibold text-foreground">Accessibility preview</p>
          <p className="mt-1 text-sm text-muted-foreground">
            Status badges, cards and tables will be previewed here.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-background p-4">
          <p className="text-sm font-semibold text-foreground">Colorblind simulation</p>
          <p className="mt-1 text-sm text-muted-foreground">
            Normal, deuteranopia, protanopia, tritanopia and grayscale previews.
          </p>
        </div>
      </div>
    </SectionCard>
  )
}
