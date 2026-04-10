import * as React from "react"
import * as SwitchPrimitives from "@radix-ui/react-switch"

import { cn } from "@/lib/utils"

const Switch = React.forwardRef<
  React.ElementRef<typeof SwitchPrimitives.Root>,
  React.ComponentPropsWithoutRef<typeof SwitchPrimitives.Root>
>(({ className, ...props }, ref) => (
  <SwitchPrimitives.Root
    className={cn(
      "peer inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-oklch(0.705 0.015 286.067) focus-visible:ring-offset-2 focus-visible:ring-offset-oklch(1 0 0) disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:bg-oklch(0.21 0.006 285.885) data-[state=unchecked]:bg-oklch(0.92 0.004 286.32) dark:focus-visible:ring-oklch(0.552 0.016 285.938) dark:focus-visible:ring-offset-oklch(0.141 0.005 285.823) dark:data-[state=checked]:bg-oklch(0.92 0.004 286.32) dark:data-[state=unchecked]:bg-oklch(1 0 0 / 15%)",
      className
    )}
    {...props}
    ref={ref}
  >
    <SwitchPrimitives.Thumb
      className={cn(
        "pointer-events-none block h-4 w-4 rounded-full bg-oklch(1 0 0) shadow-lg ring-0 transition-transform data-[state=checked]:translate-x-4 data-[state=unchecked]:translate-x-0 dark:bg-oklch(0.141 0.005 285.823)"
      )}
    />
  </SwitchPrimitives.Root>
))
Switch.displayName = SwitchPrimitives.Root.displayName

export { Switch }
