import "./GlitchText.css";
import type { CSSProperties } from "react";

type GlitchTextProps = {
  children: string;
  speed?: number;
  enableShadows?: boolean;
  enableOnHover?: boolean;
  className?: string;
};

function GlitchText({ children, speed = 1, enableShadows = true, enableOnHover = true, className = "" }: GlitchTextProps) {
  const inlineStyles = {
    "--after-duration": `${speed * 3}s`,
    "--before-duration": `${speed * 2}s`,
    "--after-shadow": enableShadows ? "-5px 0 red" : "none",
    "--before-shadow": enableShadows ? "5px 0 cyan" : "none",
  } as CSSProperties;

  const hoverClass = enableOnHover ? "enable-on-hover" : "";

  return (
    <div className={`glitch ${hoverClass} ${className}`.trim()} style={inlineStyles} data-text={children}>
      {children}
    </div>
  );
}

export default GlitchText;