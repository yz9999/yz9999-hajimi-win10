import AppKit
import Darwin
import HajimiCore
import HajimiMacOSObjC
import HajimiNativeCore
import HajimiUIComponents

// A stale/restarting privileged Helper may close its Unix socket between
// connect and write. Convert that race into EPIPE instead of terminating the
// GUI process with SIGPIPE.
signal(SIGPIPE, SIG_IGN)

/// Custom menu item view that renders a themed menu selection highlight on hover
/// and invokes its action on click without dismissing the enclosing NSMenu.
private final class StatusMenuActionItemView: NSView {
    private let highlightView = NSVisualEffectView()
    private let iconView = NSImageView()
    private let titleField = NSTextField(labelWithString: "")
    private var trackingAreaRef: NSTrackingArea?
    private var isHovered = false
    private var didFireInCurrentPress = false
    var onAction: (() -> Void)?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        wantsLayer = true
        autoresizingMask = [.width]

        highlightView.material = .selection
        highlightView.blendingMode = .withinWindow
        highlightView.state = .active
        highlightView.isEmphasized = true
        highlightView.wantsLayer = true
        highlightView.layer?.cornerRadius = 6
        highlightView.isHidden = true
        highlightView.translatesAutoresizingMaskIntoConstraints = false
        addSubview(highlightView)

        iconView.imageScaling = .scaleProportionallyDown
        iconView.contentTintColor = HajimiAppearance.accentText
        iconView.translatesAutoresizingMaskIntoConstraints = false
        addSubview(iconView)

        titleField.font = NSFont.systemFont(ofSize: 12.5, weight: .semibold)
        titleField.textColor = HajimiAppearance.accentText
        titleField.lineBreakMode = .byTruncatingTail
        titleField.translatesAutoresizingMaskIntoConstraints = false
        addSubview(titleField)

        NSLayoutConstraint.activate([
            highlightView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 6),
            highlightView.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -6),
            highlightView.topAnchor.constraint(equalTo: topAnchor, constant: 1),
            highlightView.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -1),
            iconView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20),
            iconView.centerYAnchor.constraint(equalTo: centerYAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 16),
            iconView.heightAnchor.constraint(equalToConstant: 16),
            titleField.leadingAnchor.constraint(equalTo: iconView.trailingAnchor, constant: 6),
            titleField.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -14),
            titleField.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        let pillRect = bounds.insetBy(dx: 6, dy: 1.5)
        let radius = min(8.0, max(4.0, HajimiAppearance.innerCornerRadius * 0.65))
        let path = NSBezierPath(roundedRect: pillRect, xRadius: radius, yRadius: radius)
        let active = isHovered || (enclosingMenuItem?.isHighlighted ?? false)
        let fill = active
            ? HajimiAppearance.accent.withAlphaComponent(0.24)
            : HajimiAppearance.panel.withAlphaComponent(0.72)
        let stroke = active
            ? HajimiAppearance.accent.withAlphaComponent(0.55)
            : HajimiAppearance.border
        fill.setFill()
        path.fill()
        stroke.setStroke()
        path.lineWidth = 1.0
        path.stroke()
    }

    func configure(title: String, image: NSImage?) {
        if titleField.stringValue != title {
            titleField.stringValue = title
        }
        if iconView.image !== image {
            iconView.image = image
        }
        updateHighlightAppearance()
    }

    func resetHoverState() {
        isHovered = false
        didFireInCurrentPress = false
        updateHighlightAppearance()
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let trackingAreaRef {
            removeTrackingArea(trackingAreaRef)
        }
        let options: NSTrackingArea.Options = [
            .mouseEnteredAndExited,
            .mouseMoved,
            .activeAlways,
            .inVisibleRect,
            .enabledDuringMouseDrag,
        ]
        let area = NSTrackingArea(rect: bounds, options: options, owner: self, userInfo: nil)
        addTrackingArea(area)
        trackingAreaRef = area
    }

    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

    override func mouseEntered(with event: NSEvent) {
        isHovered = true
        updateHighlightAppearance()
    }

    override func mouseMoved(with event: NSEvent) {
        let inside = bounds.contains(convert(event.locationInWindow, from: nil))
        if inside != isHovered {
            isHovered = inside
            updateHighlightAppearance()
        }
    }

    override func mouseExited(with event: NSEvent) {
        isHovered = false
        updateHighlightAppearance()
    }

    override func mouseDown(with event: NSEvent) {
        didFireInCurrentPress = true
        isHovered = true
        updateHighlightAppearance()
        onAction?()
    }

    override func mouseUp(with event: NSEvent) {
        let inside = bounds.contains(convert(event.locationInWindow, from: nil))
        if !didFireInCurrentPress && inside {
            onAction?()
        }
        didFireInCurrentPress = false
        isHovered = inside
        updateHighlightAppearance()
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if window == nil {
            resetHoverState()
        }
    }

    private func updateHighlightAppearance() {
        let active = isHovered || (enclosingMenuItem?.isHighlighted ?? false)
        highlightView.isHidden = true
        let theme = HajimiThemeCenter.shared.currentTheme
        let color: NSColor = active
            ? HajimiUITheme.color(fromHex: theme.textPrimaryHex)
            : HajimiAppearance.accentText
        titleField.textColor = color
        iconView.contentTintColor = color
        needsDisplay = true
    }
}

/// Scrollable inline list inside `StatusBarPopoverCardView`:
/// - `.rule`: Renders every Policy Group card with expandable inline member pills + per-group popup fallback.
/// - `.proxy`: Renders every real Leaf Proxy Node with single-click direct Global election + RTT badge.
private final class StatusBarModeAdaptiveListView: NSView {
    struct PolicyGroupEntryModel {
        var name: String
        var kindBadge: String
        var effectiveMember: String
        var latencyMillis: Int?
        var members: [String]
        var selectedMember: String?
    }

    struct GlobalNodeEntryModel {
        var name: String
        var protocolTag: String
        var latencyText: String
        var latencyTier: Int // 1 = fast, 2 = medium, 3 = fail/slow, 0 = untested
        var isSelected: Bool
        var isOptimal: Bool
    }

    var activeMode: OutboundMode = .rule
    var groups: [PolicyGroupEntryModel] = []
    var globalNodes: [GlobalNodeEntryModel] = []
    var memberLatencyLookup: ((String) -> String) = { _ in "" }
    var expandedGroupName: String?

    var onToggleExpandGroup: ((String) -> Void)?
    var onSelectGroupMember: ((String, String?) -> Void)?
    var onPopUpGroupMenu: ((String, NSRect) -> Void)?
    var onSelectGlobalNode: ((String) -> Void)?

    private var hoveredIndex: Int?
    private var trackingAreaRef: NSTrackingArea?

    private struct HitSlot {
        enum Kind {
            case groupHeader(String, NSRect)
            case groupMember(String, String?)
            case globalNode(String)
        }
        var rect: NSRect
        var kind: Kind
    }
    private var hitSlots: [HitSlot] = []

    override var isFlipped: Bool { true }
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

    func recomputeHeight(forWidth width: CGFloat) -> CGFloat {
        let pad: CGFloat = 6.0
        var y: CGFloat = pad
        if activeMode == .rule {
            if groups.isEmpty { return 96.0 }
            for g in groups {
                y += 38.0
                if expandedGroupName == g.name {
                    y += CGFloat(g.members.count) * 28.0 + 6.0
                }
                y += 6.0
            }
            return max(96.0, y + 2.0)
        } else if activeMode == .proxy {
            if globalNodes.isEmpty { return 96.0 }
            return max(96.0, pad + CGFloat(globalNodes.count) * 34.0 + 4.0)
        }
        return 64.0
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let trackingAreaRef { removeTrackingArea(trackingAreaRef) }
        let area = NSTrackingArea(
            rect: bounds,
            options: [.mouseEnteredAndExited, .mouseMoved, .activeAlways, .inVisibleRect],
            owner: self,
            userInfo: nil
        )
        addTrackingArea(area)
        trackingAreaRef = area
    }

    override func mouseMoved(with event: NSEvent) {
        let pt = convert(event.locationInWindow, from: nil)
        let idx = hitSlots.firstIndex { $0.rect.contains(pt) }
        if idx != hoveredIndex {
            hoveredIndex = idx
            needsDisplay = true
        }
    }

    override func mouseExited(with event: NSEvent) {
        if hoveredIndex != nil {
            hoveredIndex = nil
            needsDisplay = true
        }
    }

    override func mouseDown(with event: NSEvent) {
        let pt = convert(event.locationInWindow, from: nil)
        guard let slot = hitSlots.first(where: { $0.rect.contains(pt) }) else { return }
        switch slot.kind {
        case .groupHeader(let gName, _):
            onToggleExpandGroup?(gName)
        case .groupMember(let gName, let mName):
            onSelectGroupMember?(gName, mName)
        case .globalNode(let nName):
            onSelectGlobalNode?(nName)
        }
    }

    override func rightMouseDown(with event: NSEvent) {
        let pt = convert(event.locationInWindow, from: nil)
        guard let slot = hitSlots.first(where: { $0.rect.contains(pt) }) else { return }
        if case .groupHeader(let gName, let r) = slot.kind {
            onPopUpGroupMenu?(gName, r)
        }
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        hitSlots.removeAll(keepingCapacity: true)

        let theme = HajimiThemeCenter.shared.currentTheme
        let elevated = HajimiUITheme.color(fromHex: theme.elevatedPanelHex, alpha: 0.96)
        let muted = HajimiUITheme.color(fromHex: theme.workspaceHex, alpha: 0.65)
        let accent = HajimiUITheme.color(fromHex: theme.accentHex, alpha: 1.0)
        let accentText = HajimiUITheme.color(fromHex: theme.accentTextHex, alpha: 1.0)
        let uploadColor = HajimiUITheme.color(fromHex: theme.uploadAccentHex, alpha: 1.0)
        let textPri = HajimiUITheme.color(fromHex: theme.textPrimaryHex, alpha: 1.0)
        let textSec = HajimiUITheme.color(fromHex: theme.textSecondaryHex, alpha: 0.92)
        let subtleBorder = textSec.withAlphaComponent(theme.isDark ? 0.18 : 0.22)
        let accentBorder = accent.withAlphaComponent(0.50)

        let truncStyle = NSMutableParagraphStyle()
        truncStyle.lineBreakMode = .byTruncatingTail

        let rowLeft: CGFloat = 6.0
        let rowW: CGFloat = max(120.0, bounds.width - 12.0)
        var y: CGFloat = 6.0

        if activeMode == .rule {
            if groups.isEmpty {
                let emptyAttr: [NSAttributedString.Key: Any] = [
                    .font: NSFont.systemFont(ofSize: 12, weight: .medium),
                    .foregroundColor: textSec
                ]
                ("当前配置未定义策略组，可切换至全局代理选节点" as NSString).draw(at: NSPoint(x: 14, y: 34), withAttributes: emptyAttr)
                return
            }

            for g in groups {
                let isExp = (expandedGroupName == g.name)
                let hdrRect = NSRect(x: rowLeft, y: y, width: rowW, height: 36.0)
                let slotIdx = hitSlots.count
                hitSlots.append(HitSlot(rect: hdrRect, kind: .groupHeader(g.name, hdrRect)))
                let isHov = (hoveredIndex == slotIdx)

                let hdrPath = NSBezierPath(roundedRect: hdrRect, xRadius: 8.0, yRadius: 8.0)
                if isExp {
                    accent.withAlphaComponent(0.14).setFill()
                    hdrPath.fill()
                    accentBorder.setStroke()
                } else {
                    (isHov ? accent.withAlphaComponent(0.10) : elevated).setFill()
                    hdrPath.fill()
                    (isHov ? accentBorder : subtleBorder).setStroke()
                }
                hdrPath.lineWidth = 1.0
                hdrPath.stroke()

                let gNameAttrs: [NSAttributedString.Key: Any] = [
                    .font: NSFont.systemFont(ofSize: 12.0, weight: .bold),
                    .foregroundColor: textPri,
                    .paragraphStyle: truncStyle
                ]
                (g.name as NSString).draw(in: NSRect(x: hdrRect.minX + 10, y: hdrRect.minY + 4, width: rowW * 0.50, height: 16), withAttributes: gNameAttrs)

                let badgeAttrs: [NSAttributedString.Key: Any] = [
                    .font: NSFont.systemFont(ofSize: 10.0, weight: .medium),
                    .foregroundColor: textSec
                ]
                ("\(g.kindBadge) · \(g.members.count) 项" as NSString).draw(at: NSPoint(x: hdrRect.minX + 10, y: hdrRect.minY + 19), withAttributes: badgeAttrs)

                var rightSummary = g.effectiveMember
                if let ms = g.latencyMillis, ms > 0 {
                    rightSummary += " · \(ms)ms"
                }
                rightSummary += isExp ? " ▴" : " ▾"
                let effAttrs: [NSAttributedString.Key: Any] = [
                    .font: NSFont.systemFont(ofSize: 11.5, weight: .semibold),
                    .foregroundColor: accentText,
                    .paragraphStyle: truncStyle
                ]
                let effSize = (rightSummary as NSString).size(withAttributes: effAttrs)
                let effW = min(rowW * 0.46, ceil(effSize.width) + 2)
                (rightSummary as NSString).draw(
                    in: NSRect(x: hdrRect.maxX - 10 - effW, y: hdrRect.minY + 10, width: effW, height: 16),
                    withAttributes: effAttrs
                )

                y += 38.0
                if isExp {
                    for m in g.members {
                        let mRect = NSRect(x: rowLeft + 10, y: y, width: rowW - 14, height: 26.0)
                        let mIdx = hitSlots.count
                        hitSlots.append(HitSlot(rect: mRect, kind: .groupMember(g.name, m)))
                        let mHov = (hoveredIndex == mIdx)
                        let isSel = (g.selectedMember == m) || (g.selectedMember == nil && g.effectiveMember == m)

                        let mPath = NSBezierPath(roundedRect: mRect, xRadius: 6.0, yRadius: 6.0)
                        if isSel {
                            accent.withAlphaComponent(0.18).setFill()
                            mPath.fill()
                            accentBorder.setStroke()
                            mPath.stroke()
                        } else if mHov {
                            accent.withAlphaComponent(0.09).setFill()
                            mPath.fill()
                        } else {
                            muted.setFill()
                            mPath.fill()
                        }

                        let dot = isSel ? "● " : "○ "
                        let mTitleAttrs: [NSAttributedString.Key: Any] = [
                            .font: NSFont.systemFont(ofSize: 11.5, weight: isSel ? .bold : .medium),
                            .foregroundColor: isSel ? accentText : textPri,
                            .paragraphStyle: truncStyle
                        ]
                        ("\(dot)\(m)" as NSString).draw(
                            in: NSRect(x: mRect.minX + 8, y: mRect.minY + 5, width: mRect.width - 74, height: 16),
                            withAttributes: mTitleAttrs
                        )

                        let latStr = memberLatencyLookup(m)
                        if !latStr.isEmpty {
                            let latAttrs: [NSAttributedString.Key: Any] = [
                                .font: NSFont.monospacedDigitSystemFont(ofSize: 10.5, weight: .semibold),
                                .foregroundColor: uploadColor
                            ]
                            let lSz = (latStr as NSString).size(withAttributes: latAttrs)
                            (latStr as NSString).draw(at: NSPoint(x: mRect.maxX - 8 - lSz.width, y: mRect.minY + 5.5), withAttributes: latAttrs)
                        }
                        y += 28.0
                    }
                    y += 4.0
                }
                y += 6.0
            }
            return
        }

        if activeMode == .proxy {
            if globalNodes.isEmpty {
                let emptyAttr: [NSAttributedString.Key: Any] = [
                    .font: NSFont.systemFont(ofSize: 12, weight: .medium),
                    .foregroundColor: textSec
                ]
                ("当前档案暂无可用代理节点，请先更新订阅或导入配置" as NSString).draw(at: NSPoint(x: 14, y: 34), withAttributes: emptyAttr)
                return
            }

            for nd in globalNodes {
                let nRect = NSRect(x: rowLeft, y: y, width: rowW, height: 30.0)
                let slotIdx = hitSlots.count
                hitSlots.append(HitSlot(rect: nRect, kind: .globalNode(nd.name)))
                let isHov = (hoveredIndex == slotIdx)

                let nPath = NSBezierPath(roundedRect: nRect, xRadius: 8.0, yRadius: 8.0)
                if nd.isSelected {
                    accent.withAlphaComponent(0.18).setFill()
                    nPath.fill()
                    accentBorder.setStroke()
                    nPath.lineWidth = 1.2
                    nPath.stroke()
                } else {
                    (isHov ? accent.withAlphaComponent(0.10) : elevated).setFill()
                    nPath.fill()
                    (isHov ? accentBorder : subtleBorder).setStroke()
                    nPath.lineWidth = 1.0
                    nPath.stroke()
                }

                let radio = nd.isSelected ? "● " : "○ "
                let optSuffix = nd.isOptimal ? " ★最优" : ""
                let leftLabel = "\(radio)\(nd.name)"
                let nameAttrs: [NSAttributedString.Key: Any] = [
                    .font: NSFont.systemFont(ofSize: 12.0, weight: nd.isSelected ? .bold : .medium),
                    .foregroundColor: nd.isSelected ? accentText : textPri,
                    .paragraphStyle: truncStyle
                ]
                (leftLabel as NSString).draw(
                    in: NSRect(x: nRect.minX + 9, y: nRect.minY + 7, width: rowW - 128, height: 16),
                    withAttributes: nameAttrs
                )

                let protoBadge = "\(nd.protocolTag)\(optSuffix)"
                let protoAttrs: [NSAttributedString.Key: Any] = [
                    .font: NSFont.systemFont(ofSize: 10.0, weight: .semibold),
                    .foregroundColor: nd.isOptimal ? accentText : textSec
                ]
                let pSize = (protoBadge as NSString).size(withAttributes: protoAttrs)

                let latColor: NSColor
                switch nd.latencyTier {
                case 1: latColor = accentText
                case 2: latColor = .systemOrange
                case 3: latColor = .systemRed
                default: latColor = textSec
                }
                let latAttrs: [NSAttributedString.Key: Any] = [
                    .font: NSFont.monospacedDigitSystemFont(ofSize: 11.0, weight: .bold),
                    .foregroundColor: latColor
                ]
                let lSize = (nd.latencyText as NSString).size(withAttributes: latAttrs)
                let latX = nRect.maxX - 9 - lSize.width
                (nd.latencyText as NSString).draw(at: NSPoint(x: latX, y: nRect.minY + 7.5), withAttributes: latAttrs)
                (protoBadge as NSString).draw(at: NSPoint(x: latX - 8 - pSize.width, y: nRect.minY + 8.5), withAttributes: protoAttrs)

                y += 34.0
            }
        }
    }
}

/// Interactive three-state status-bar popover card:
/// - Rule Mode (`.rule`): Displays Policy Groups list for per-group routing configuration.
/// - Global Mode (`.proxy`): Displays direct Leaf Proxy Node election list (bypasses groups/rules).
/// - Direct Mode (`.direct`): Displays compact Direct passthrough card.
private final class StatusBarPopoverCardView: NSView {
    struct Model {
        var isRunning: Bool
        var subtitle: String
        var latencyMillis: Int
        var activeMode: OutboundMode
        var sectionHeaderLeft: String
        var sectionHeaderAction: String
        var groups: [StatusBarModeAdaptiveListView.PolicyGroupEntryModel]
        var globalNodes: [StatusBarModeAdaptiveListView.GlobalNodeEntryModel]
        var isEnhancedMode: Bool
        var isSystemProxy: Bool
        var themeBadgeText: String
    }

    static let popoverWidth: CGFloat = 380.0
    static let expandedHeight: CGFloat = 424.0
    static let compactDirectHeight: CGFloat = 252.0

    var onSelectMode: ((OutboundMode) -> Void)?
    var onClickLatencyPill: (() -> Void)?
    var onClickSpeedTestRow: (() -> Void)?
    var onSelectGroupMember: ((String, String?) -> Void)?
    var onPopUpGroupMenu: ((String, NSView) -> Void)?
    var onSelectGlobalNode: ((String) -> Void)?
    var onToggleEnhancedMode: (() -> Void)?
    var onToggleSystemProxy: (() -> Void)?
    var onClickThemeSelector: ((NSView) -> Void)?
    var onOpenConsole: (() -> Void)?
    var onQuitApp: (() -> Void)?

    var memberLatencyLookup: ((String) -> String) {
        get { listContentView.memberLatencyLookup }
        set { listContentView.memberLatencyLookup = newValue }
    }

    private var model = Model(
        isRunning: false,
        subtitle: "代理引擎未启动",
        latencyMillis: -1,
        activeMode: .rule,
        sectionHeaderLeft: "🧭 策略组分流配置",
        sectionHeaderAction: "⚡ 测速",
        groups: [],
        globalNodes: [],
        isEnhancedMode: false,
        isSystemProxy: false,
        themeBadgeText: "#01 翡翠原石"
    )

    private let catImageView = NSImageView()
    private let listScrollView = NSScrollView()
    private let listContentView = StatusBarModeAdaptiveListView(frame: NSRect(x: 0, y: 0, width: 340, height: 210))
    private let nodeAnchorView = NSView(frame: .zero)
    private let themeAnchorView = NSView(frame: .zero)

    private var hoveredMode: OutboundMode?
    private var isLatencyHovered = false
    private var isSectionActionHovered = false
    private var hoveredFooterIndex: Int?
    private var trackingAreaRef: NSTrackingArea?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        wantsLayer = true
        catImageView.image = Self.loadBrandCatAvatar()
        catImageView.imageScaling = .scaleProportionallyUpOrDown
        catImageView.frame = NSRect(x: 20, y: 18, width: 38, height: 38)
        addSubview(catImageView)

        listScrollView.drawsBackground = false
        listScrollView.hasVerticalScroller = true
        listScrollView.autohidesScrollers = true
        listScrollView.borderType = .noBorder
        listScrollView.documentView = listContentView
        addSubview(listScrollView)

        addSubview(nodeAnchorView)
        addSubview(themeAnchorView)

        listContentView.onToggleExpandGroup = { [weak self] gName in
            guard let self else { return }
            if self.listContentView.expandedGroupName == gName {
                self.listContentView.expandedGroupName = nil
            } else {
                self.listContentView.expandedGroupName = gName
            }
            self.relayoutListDocument()
        }
        listContentView.onSelectGroupMember = { [weak self] gName, mName in
            self?.onSelectGroupMember?(gName, mName)
        }
        listContentView.onPopUpGroupMenu = { [weak self] gName, rectInDoc in
            guard let self else { return }
            let rectInSelf = self.convert(rectInDoc, from: self.listContentView)
            self.nodeAnchorView.frame = rectInSelf
            self.onPopUpGroupMenu?(gName, self.nodeAnchorView)
        }
        listContentView.onSelectGlobalNode = { [weak self] nName in
            self?.onSelectGlobalNode?(nName)
        }
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override var isFlipped: Bool { true }

    static func loadBrandCatAvatar() -> NSImage {
        let img = HajimiBrandIcon.makeImage()
        if !img.isTemplate { return img }
        let fallbackPaths = [
            "Resources/Hajimi.icns",
            "Resources/Hajimi.png",
            Bundle.main.bundlePath + "/Contents/Resources/Hajimi.icns"
        ]
        for path in fallbackPaths {
            if let loaded = NSImage(contentsOfFile: path), loaded.isValid {
                loaded.isTemplate = false
                return loaded
            }
        }
        return img
    }

    var preferredPopoverSize: NSSize {
        NSSize(
            width: Self.popoverWidth,
            height: model.activeMode == .direct ? Self.compactDirectHeight : Self.expandedHeight
        )
    }

    private func relayoutListDocument() {
        let box = centerSectionRect
        if model.activeMode == .direct {
            listScrollView.isHidden = true
        } else {
            listScrollView.isHidden = false
            let scrollRect = NSRect(x: box.minX + 2, y: box.minY + 30, width: box.width - 4, height: box.height - 34)
            listScrollView.frame = scrollRect
            let docW = max(200.0, scrollRect.width)
            let docH = listContentView.recomputeHeight(forWidth: docW)
            listContentView.frame = NSRect(x: 0, y: 0, width: docW, height: max(scrollRect.height, docH))
            listContentView.needsDisplay = true
        }
        needsDisplay = true
    }

    func update(with newModel: Model) {
        self.model = newModel
        listContentView.activeMode = newModel.activeMode
        listContentView.groups = newModel.groups
        listContentView.globalNodes = newModel.globalNodes
        if newModel.activeMode == .rule,
           let exp = listContentView.expandedGroupName,
           !newModel.groups.contains(where: { $0.name == exp }) {
            listContentView.expandedGroupName = newModel.groups.first?.name
        } else if newModel.activeMode == .rule && listContentView.expandedGroupName == nil {
            listContentView.expandedGroupName = newModel.groups.first?.name
        }
        relayoutListDocument()
    }

    override func setFrameSize(_ newSize: NSSize) {
        super.setFrameSize(newSize)
        relayoutListDocument()
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let trackingAreaRef { removeTrackingArea(trackingAreaRef) }
        let area = NSTrackingArea(
            rect: bounds,
            options: [.mouseEnteredAndExited, .mouseMoved, .activeAlways, .inVisibleRect],
            owner: self,
            userInfo: nil
        )
        addTrackingArea(area)
        trackingAreaRef = area
    }

    private var latencyPillRect: NSRect {
        let text = latencyBadgeText
        let font = NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .bold)
        let w = max(56.0, ceil((text as NSString).size(withAttributes: [.font: font]).width) + 20.0)
        return NSRect(x: bounds.width - 20.0 - w, y: 24.0, width: w, height: 25.0)
    }

    private func modeButtonRect(for index: Int) -> NSRect {
        let left: CGFloat = 20.0
        let totalW: CGFloat = bounds.width - 40.0
        let gap: CGFloat = 8.0
        let btnW = floor((totalW - gap * 2.0) / 3.0)
        let x = left + CGFloat(index) * (btnW + gap)
        return NSRect(x: x, y: 70.0, width: btnW, height: 34.0)
    }

    private var centerSectionRect: NSRect {
        let h: CGFloat = (model.activeMode == .direct) ? 82.0 : 254.0
        return NSRect(x: 20.0, y: 114.0, width: bounds.width - 40.0, height: h)
    }

    private var sectionActionRect: NSRect {
        let box = centerSectionRect
        return NSRect(x: box.maxX - 92.0, y: box.minY + 4.0, width: 86.0, height: 22.0)
    }

    private func footerButtonRect(for index: Int) -> NSRect {
        let y: CGFloat = bounds.height - 42.0
        let h: CGFloat = 28.0
        let left: CGFloat = 20.0
        let totalW = bounds.width - 40.0
        let gap: CGFloat = 6.0
        let quitW: CGFloat = 32.0
        let remainW = totalW - quitW - gap * 4.0
        let w0 = floor(remainW * 0.28)
        let w1 = floor(remainW * 0.26)
        let w2 = floor(remainW * 0.23)
        let w3 = remainW - w0 - w1 - w2
        let widths = [w0, w1, w2, w3, quitW]
        var curX = left
        for i in 0..<index { curX += widths[i] + gap }
        return NSRect(x: curX, y: y, width: widths[index], height: h)
    }

    private var latencyBadgeText: String {
        if model.activeMode == .direct { return "DIRECT" }
        if model.latencyMillis > 0 { return "\(model.latencyMillis) ms" }
        if model.latencyMillis == 0 { return "超时" }
        return "测速"
    }

    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

    override func mouseMoved(with event: NSEvent) {
        let pt = convert(event.locationInWindow, from: nil)
        let modes: [OutboundMode] = [.rule, .proxy, .direct]
        var newHoveredMode: OutboundMode?
        for (i, m) in modes.enumerated() where modeButtonRect(for: i).contains(pt) {
            newHoveredMode = m
            break
        }
        let newLatHover = latencyPillRect.contains(pt)
        let newActHover = model.activeMode != .direct && sectionActionRect.contains(pt)
        var newFooterHover: Int?
        for i in 0..<5 where footerButtonRect(for: i).contains(pt) {
            newFooterHover = i
            break
        }
        if newHoveredMode != hoveredMode ||
           newLatHover != isLatencyHovered ||
           newActHover != isSectionActionHovered ||
           newFooterHover != hoveredFooterIndex {
            hoveredMode = newHoveredMode
            isLatencyHovered = newLatHover
            isSectionActionHovered = newActHover
            hoveredFooterIndex = newFooterHover
            needsDisplay = true
        }
    }

    override func mouseExited(with event: NSEvent) {
        hoveredMode = nil
        isLatencyHovered = false
        isSectionActionHovered = false
        hoveredFooterIndex = nil
        needsDisplay = true
    }

    override func mouseDown(with event: NSEvent) {
        let pt = convert(event.locationInWindow, from: nil)
        let modes: [OutboundMode] = [.rule, .proxy, .direct]
        for (i, m) in modes.enumerated() where modeButtonRect(for: i).contains(pt) {
            onSelectMode?(m)
            return
        }
        if latencyPillRect.contains(pt) {
            onClickLatencyPill?()
            return
        }
        if model.activeMode != .direct && sectionActionRect.contains(pt) {
            onClickSpeedTestRow?()
            return
        }
        for i in 0..<5 where footerButtonRect(for: i).contains(pt) {
            switch i {
            case 0: onToggleEnhancedMode?()
            case 1: onToggleSystemProxy?()
            case 2:
                themeAnchorView.frame = footerButtonRect(for: 2)
                onClickThemeSelector?(themeAnchorView)
            case 3: onOpenConsole?()
            case 4: onQuitApp?()
            default: break
            }
            return
        }
    }

    private static func isLightColor(_ color: NSColor) -> Bool {
        guard let rgb = color.usingColorSpace(.deviceRGB) else { return true }
        let lum = 0.299 * rgb.redComponent + 0.587 * rgb.greenComponent + 0.114 * rgb.blueComponent
        return lum > 0.52
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)

        let theme = HajimiThemeCenter.shared.currentTheme
        let panelColor = HajimiUITheme.color(fromHex: theme.panelHex, alpha: 0.98)
        let workspaceColor = HajimiUITheme.color(fromHex: theme.workspaceHex, alpha: 0.95)
        let elevatedColor = HajimiUITheme.color(fromHex: theme.elevatedPanelHex, alpha: 0.98)
        let accentColor = HajimiUITheme.color(fromHex: theme.accentHex, alpha: 1.0)
        let accentTextColor = HajimiUITheme.color(fromHex: theme.accentTextHex, alpha: 1.0)
        let uploadColor = HajimiUITheme.color(fromHex: theme.uploadAccentHex, alpha: 1.0)
        let textPrimary = HajimiUITheme.color(fromHex: theme.textPrimaryHex, alpha: 1.0)
        let textSecondary = HajimiUITheme.color(fromHex: theme.textSecondaryHex, alpha: 0.92)
        let borderColor = accentColor.withAlphaComponent(CGFloat(max(0.14, min(0.65, theme.borderAlpha + 0.04))))
        let subtleBorder = textSecondary.withAlphaComponent(theme.isDark ? 0.18 : 0.22)
        let activePillTextColor: NSColor = Self.isLightColor(accentColor)
            ? NSColor(calibratedRed: 0.02, green: 0.14, blue: 0.10, alpha: 1.0)
            : .white

        let outerRadius = CGFloat(max(12.0, min(22.0, theme.cardCornerRadius)))
        let innerRadius = CGFloat(max(8.0, min(14.0, theme.innerCornerRadius)))

        let cardRect = bounds.insetBy(dx: 1.0, dy: 1.0)
        let cardPath = NSBezierPath(roundedRect: cardRect, xRadius: outerRadius, yRadius: outerRadius)
        NSGraphicsContext.saveGraphicsState()
        cardPath.addClip()
        if let grad = NSGradient(starting: elevatedColor, ending: panelColor) {
            grad.draw(in: cardRect, angle: 90.0)
        } else {
            panelColor.setFill()
            cardPath.fill()
        }
        NSGraphicsContext.restoreGraphicsState()
        borderColor.setStroke()
        cardPath.lineWidth = 1.0
        cardPath.stroke()

        let titleText = model.isRunning ? "哈基米状态栏 · 运行中" : "哈基米状态栏 · 待机"
        let titleAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 14.0, weight: .bold),
            .foregroundColor: textPrimary
        ]
        (titleText as NSString).draw(at: NSPoint(x: 68.0, y: 17.0), withAttributes: titleAttrs)

        let subStyle = NSMutableParagraphStyle()
        subStyle.lineBreakMode = .byTruncatingTail
        let subAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 11.5, weight: .medium),
            .foregroundColor: textSecondary,
            .paragraphStyle: subStyle
        ]
        let maxSubW = latencyPillRect.minX - 74.0
        (model.subtitle as NSString).draw(
            in: NSRect(x: 68.0, y: 38.0, width: max(80.0, maxSubW), height: 18.0),
            withAttributes: subAttrs
        )

        let latRect = latencyPillRect
        let latPath = NSBezierPath(roundedRect: latRect, xRadius: latRect.height / 2.0, yRadius: latRect.height / 2.0)
        let latFill: NSColor
        let latTextColor: NSColor
        if model.activeMode == .direct {
            latFill = accentColor.withAlphaComponent(0.18)
            latTextColor = accentTextColor
        } else if model.latencyMillis > 0 {
            latFill = isLatencyHovered ? accentTextColor : accentColor
            latTextColor = activePillTextColor
        } else if model.latencyMillis == 0 {
            latFill = NSColor.systemRed.withAlphaComponent(0.22)
            latTextColor = .systemRed
        } else {
            latFill = accentColor.withAlphaComponent(isLatencyHovered ? 0.30 : 0.18)
            latTextColor = accentTextColor
        }
        latFill.setFill()
        latPath.fill()

        let latAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 11.5, weight: .bold),
            .foregroundColor: latTextColor
        ]
        let latStr = latencyBadgeText as NSString
        let latSize = latStr.size(withAttributes: latAttrs)
        latStr.draw(
            at: NSPoint(x: latRect.midX - latSize.width / 2.0, y: latRect.midY - latSize.height / 2.0),
            withAttributes: latAttrs
        )

        let modeSpecs: [(OutboundMode, String)] = [
            (.rule, "规则分流"),
            (.proxy, "全局代理"),
            (.direct, "全局直连")
        ]
        for (idx, spec) in modeSpecs.enumerated() {
            let mRect = modeButtonRect(for: idx)
            let isSelected = (model.activeMode == spec.0)
            let isHovered = (hoveredMode == spec.0)
            let btnRadius = max(7.0, min(10.0, innerRadius))
            let mPath = NSBezierPath(roundedRect: mRect, xRadius: btnRadius, yRadius: btnRadius)

            if isSelected {
                (isHovered ? accentTextColor : accentColor).setFill()
                mPath.fill()
            } else {
                let inactiveFill = isHovered
                    ? accentColor.withAlphaComponent(0.14)
                    : workspaceColor.withAlphaComponent(0.45)
                inactiveFill.setFill()
                mPath.fill()
                (isHovered ? borderColor : subtleBorder).setStroke()
                mPath.lineWidth = 1.0
                mPath.stroke()
            }

            let mAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 12.5, weight: .bold),
                .foregroundColor: isSelected ? activePillTextColor : textPrimary
            ]
            let mStr = spec.1 as NSString
            let mSize = mStr.size(withAttributes: mAttrs)
            mStr.draw(
                at: NSPoint(x: mRect.midX - mSize.width / 2.0, y: mRect.midY - mSize.height / 2.0),
                withAttributes: mAttrs
            )
        }

        let box = centerSectionRect
        let boxPath = NSBezierPath(roundedRect: box, xRadius: innerRadius, yRadius: innerRadius)
        workspaceColor.withAlphaComponent(theme.isDark ? 0.58 : 0.72).setFill()
        boxPath.fill()
        subtleBorder.setStroke()
        boxPath.lineWidth = 1.0
        boxPath.stroke()

        if model.activeMode == .direct {
            let dTitleAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 12.5, weight: .bold),
                .foregroundColor: accentTextColor
            ]
            ("● 全局直连模式已生效" as NSString).draw(at: NSPoint(x: box.minX + 14.0, y: box.minY + 18.0), withAttributes: dTitleAttrs)
            let dSubAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 11.5, weight: .regular),
                .foregroundColor: textSecondary
            ]
            ("所有网络连接绕过分流规则与代理节点，直出物理网卡" as NSString).draw(at: NSPoint(x: box.minX + 14.0, y: box.minY + 42.0), withAttributes: dSubAttrs)
        } else {
            let hdrLeftAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 11.0, weight: .semibold),
                .foregroundColor: textSecondary
            ]
            (model.sectionHeaderLeft as NSString).draw(at: NSPoint(x: box.minX + 10.0, y: box.minY + 8.0), withAttributes: hdrLeftAttrs)

            let actRect = sectionActionRect
            if isSectionActionHovered {
                let actPath = NSBezierPath(roundedRect: actRect, xRadius: 6, yRadius: 6)
                accentColor.withAlphaComponent(0.14).setFill()
                actPath.fill()
            }
            let actAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 11.0, weight: .bold),
                .foregroundColor: accentTextColor
            ]
            let aStr = model.sectionHeaderAction as NSString
            let aSz = aStr.size(withAttributes: actAttrs)
            aStr.draw(at: NSPoint(x: actRect.maxX - 6.0 - aSz.width, y: box.minY + 8.0), withAttributes: actAttrs)

            let sep = NSBezierPath()
            sep.move(to: NSPoint(x: box.minX + 8.0, y: box.minY + 29.0))
            sep.line(to: NSPoint(x: box.maxX - 8.0, y: box.minY + 29.0))
            subtleBorder.setStroke()
            sep.lineWidth = 1.0
            sep.stroke()
        }

        let footerItems: [(String, Bool, NSColor)] = [
            (model.isEnhancedMode ? "● 增强模式" : "○ 增强模式", model.isEnhancedMode, uploadColor),
            (model.isSystemProxy ? "● 系统代理" : "○ 系统代理", model.isSystemProxy, accentTextColor),
            ("🎨 主题", false, accentTextColor),
            ("控制台", false, textPrimary),
            ("⏻", false, textSecondary)
        ]
        for (idx, item) in footerItems.enumerated() {
            let fRect = footerButtonRect(for: idx)
            let isHov = (hoveredFooterIndex == idx)
            let fPath = NSBezierPath(roundedRect: fRect, xRadius: 7.0, yRadius: 7.0)
            let fill: NSColor
            let stroke: NSColor
            let fg: NSColor
            if item.1 {
                fill = item.2.withAlphaComponent(isHov ? 0.26 : 0.16)
                stroke = item.2.withAlphaComponent(0.45)
                fg = item.2
            } else {
                fill = isHov ? accentColor.withAlphaComponent(0.14) : workspaceColor.withAlphaComponent(0.38)
                stroke = isHov ? borderColor : subtleBorder
                fg = isHov ? textPrimary : textSecondary
            }
            fill.setFill()
            fPath.fill()
            stroke.setStroke()
            fPath.lineWidth = 1.0
            fPath.stroke()

            let fAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 11.0, weight: item.1 ? .bold : .semibold),
                .foregroundColor: fg
            ]
            let fStr = item.0 as NSString
            let fSize = fStr.size(withAttributes: fAttrs)
            fStr.draw(
                at: NSPoint(x: fRect.midX - fSize.width / 2.0, y: fRect.midY - fSize.height / 2.0),
                withAttributes: fAttrs
            )
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSPopoverDelegate {
    private var mainWindowController: MainWindowController?
    private var statusItem: NSStatusItem?
    private let statusPopover = NSPopover()
    private let popoverViewController = NSViewController()
    private let popoverCardView = StatusBarPopoverCardView(frame: NSRect(x: 0, y: 0, width: StatusBarPopoverCardView.popoverWidth, height: StatusBarPopoverCardView.expandedHeight))
    private var outsideClickMonitor: Any?
    private var trafficTicker: Timer?
    private var lastTrafficReadoutKey: String = ""
    private var lastUploadBytesPerSecond: Double = 0
    private var lastDownloadBytesPerSecond: Double = 0
    private var processActivityToken: NSObjectProtocol?

    private final class PolicyGroupMenuEntry {
        let groupName: String
        let item: NSMenuItem
        let submenu: NSMenu
        let testItem: NSMenuItem
        let testView: StatusMenuActionItemView
        let defaultItem: NSMenuItem
        let separatorItem = NSMenuItem.separator()

        init(groupName: String, onTestGroup: @escaping () -> Void, target: AnyObject, defaultAction: Selector) {
            self.groupName = groupName
            self.item = NSMenuItem(title: groupName, action: nil, keyEquivalent: "")
            self.submenu = NSMenu(title: groupName)
            self.submenu.minimumWidth = 280
            self.testItem = NSMenuItem(title: "⚡ 测速本组节点", action: nil, keyEquivalent: "")
            self.testView = StatusMenuActionItemView(frame: NSRect(x: 0, y: 0, width: 280, height: 26))
            self.testView.onAction = onTestGroup
            self.testItem.view = self.testView
            self.defaultItem = NSMenuItem(title: "配置默认", action: defaultAction, keyEquivalent: "")
            self.defaultItem.target = target
            self.defaultItem.representedObject = ["group": groupName]
            self.submenu.addItem(self.testItem)
            self.submenu.addItem(self.defaultItem)
            self.submenu.addItem(self.separatorItem)
            self.item.submenu = self.submenu
        }
    }

    private let nodePickerMenu = NSMenu(title: "节点与策略组选择")
    private let globalTestAllItem = NSMenuItem(title: "⚡ 一键测速全部节点", action: nil, keyEquivalent: "")
    private let globalTestAllView = StatusMenuActionItemView(frame: NSRect(x: 0, y: 0, width: 280, height: 26))
    private let globalTestSeparator = NSMenuItem.separator()
    private let uiThemeMenu = NSMenu(title: "UI 主题切换")
    private let openThemeSettingsItem = NSMenuItem(title: "打开 UI 主题设置与导入面板…", action: #selector(openThemeSettingsFromStatusItem), keyEquivalent: "")
    private var policyGroupMenuEntries: [String: PolicyGroupMenuEntry] = [:]

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Prevent macOS App Nap from throttling proxy queues, timers, and
        // Helper heartbeats when the screen turns off (Display Sleep) or the
        // main window is closed to the status bar, while still allowing normal
        // idle system sleep.
        processActivityToken = ProcessInfo.processInfo.beginActivity(
            options: [.userInitiatedAllowingIdleSystemSleep, .latencyCritical],
            reason: "Hajimi Network Proxy and Packet Tunnel Engine"
        )
        buildMainMenu()
        let controller = MainWindowController()
        mainWindowController = controller
        controller.onStatusBarStateChanged = { [weak self] in
            guard let self, let ctrl = self.mainWindowController else { return }
            self.syncStatusPopoverAppearance()
            self.refreshPopoverCard(controller: ctrl)
            self.updateOpenNodePickerMenuInPlace(controller: ctrl)
        }
        buildStatusItem()
        NotificationCenter.default.addObserver(
            forName: HajimiThemeCenter.didChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            self.syncStatusPopoverAppearance()
            self.lastTrafficReadoutKey = ""
            self.refreshTrafficReadout()
            if let ctrl = self.mainWindowController {
                self.refreshPopoverCard(controller: ctrl)
            }
        }
        controller.launch()
    }

    /// Closing the red window button hides the UI but leaves the proxy and its
    /// menu-bar controls running. Only “退出哈基米” performs network cleanup.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { mainWindowController?.revealFromStatusItem() }
        return true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // Always drop the helper tunnel first. A quit that leaves utun routes
        // up black-holes the machine until the helper's liveness timer fires.
        mainWindowController?.shutdownEnhancedModeForQuit()
        do {
            try mainWindowController?.restoreSystemProxyBeforeQuit()
            return .terminateNow
        } catch {
            let alert = NSAlert()
            alert.messageText = "无法恢复系统代理"
            alert.informativeText = error.localizedDescription
            alert.addButton(withTitle: "取消退出")
            alert.addButton(withTitle: "仍然退出")
            let choice = alert.runModal()
            if choice == .alertSecondButtonReturn {
                // User insisted — make sure helper routes are still gone.
                mainWindowController?.shutdownEnhancedModeForQuit()
                return .terminateNow
            }
            return .terminateCancel
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        if let token = processActivityToken {
            ProcessInfo.processInfo.endActivity(token)
            processActivityToken = nil
        }
        if let monitor = outsideClickMonitor {
            NSEvent.removeMonitor(monitor)
            outsideClickMonitor = nil
        }
        mainWindowController?.shutdownEnhancedModeForQuit()
    }

    private func buildMainMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem()
        main.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "关于哈基米", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "退出哈基米", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu

        let editItem = NSMenuItem()
        main.addItem(editItem)
        let editMenu = NSMenu(title: "编辑")
        editMenu.addItem(withTitle: "撤销", action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "剪切", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "复制", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "粘贴", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "全选", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = editMenu
        NSApp.mainMenu = main
    }

    private static func menuSymbol(_ name: String, tint: NSColor? = nil) -> NSImage? {
        guard let base = NSImage(systemSymbolName: name, accessibilityDescription: nil) else { return nil }
        let baseConfig = NSImage.SymbolConfiguration(pointSize: 13, weight: .medium)
        let color = tint ?? HajimiAppearance.accentText
        let paletteConfig = baseConfig.applying(NSImage.SymbolConfiguration(paletteColors: [color]))
        let configured = base.withSymbolConfiguration(paletteConfig) ?? base
        configured.isTemplate = false
        return configured
    }

    private static func makeMenuBarCatImage() -> NSImage {
        let source = StatusBarPopoverCardView.loadBrandCatAvatar()
        if source.isTemplate {
            return source
        }
        let targetSize = NSSize(width: 18, height: 18)
        let resized = NSImage(size: targetSize, flipped: false) { rect in
            NSGraphicsContext.current?.imageInterpolation = .high
            source.draw(in: rect, from: .zero, operation: .sourceOver, fraction: 1.0)
            return true
        }
        resized.isTemplate = false
        return resized
    }

    private static func themePrimaryTextColor() -> NSColor {
        HajimiUITheme.color(fromHex: HajimiThemeCenter.shared.currentTheme.textPrimaryHex)
    }

    private static func themeSecondaryTextColor() -> NSColor {
        HajimiUITheme.color(fromHex: HajimiThemeCenter.shared.currentTheme.textSecondaryHex)
    }

    private func syncStatusPopoverAppearance() {
        let appearance = HajimiThemeCenter.shared.effectiveMenuAppearance
            ?? NSAppearance(named: HajimiThemeCenter.shared.currentTheme.isDark ? .darkAqua : .aqua)
        statusPopover.appearance = appearance
        popoverCardView.appearance = appearance
        nodePickerMenu.appearance = appearance
        uiThemeMenu.appearance = appearance
        popoverCardView.needsDisplay = true
        for entry in policyGroupMenuEntries.values {
            entry.submenu.appearance = appearance
        }
    }

    private func buildStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = item.button {
            button.image = Self.makeMenuBarCatImage()
            Self.configureTrafficButton(button)
            button.target = self
            button.action = #selector(toggleStatusPopover(_:))
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
            button.toolTip = "哈基米"
        }

        popoverViewController.view = popoverCardView
        statusPopover.contentSize = popoverCardView.frame.size
        statusPopover.behavior = .transient
        statusPopover.animates = true
        statusPopover.contentViewController = popoverViewController
        statusPopover.delegate = self

        globalTestAllView.configure(
            title: "⚡ 一键测速全部节点",
            image: Self.menuSymbol("bolt.horizontal.circle", tint: HajimiAppearance.accentText)
        )
        globalTestAllView.onAction = { [weak self] in
            self?.testAllNodesFromStatusItem()
        }
        globalTestAllItem.view = globalTestAllView
        nodePickerMenu.minimumWidth = 280
        uiThemeMenu.minimumWidth = 280
        openThemeSettingsItem.target = self

        popoverCardView.onSelectMode = { [weak self] mode in
            guard let self, let ctrl = self.mainWindowController else { return }
            ctrl.selectOutboundModeFromStatusItem(mode)
            self.refreshPopoverCard(controller: ctrl)
        }
        popoverCardView.onClickLatencyPill = { [weak self] in
            guard let self, let ctrl = self.mainWindowController else { return }
            ctrl.testActiveNodeFromStatusItem()
            self.refreshPopoverCard(controller: ctrl)
        }
        popoverCardView.memberLatencyLookup = { [weak self] memberName in
            guard let ctrl = self?.mainWindowController else { return "" }
            let item = ctrl.statusItemNodeItem(named: memberName)
            if let ms = item.latencyMillis { return "\(ms) ms" }
            if item.protocolTag == "GROUP" { return "策略组" }
            if memberName.uppercased() == "DIRECT" { return "直连" }
            return ""
        }
        popoverCardView.onClickSpeedTestRow = { [weak self] in
            guard let self, let ctrl = self.mainWindowController else { return }
            ctrl.testAllNodesFromStatusItem()
            self.refreshPopoverCard(controller: ctrl)
        }
        popoverCardView.onSelectGroupMember = { [weak self] groupName, memberName in
            guard let self, let ctrl = self.mainWindowController else { return }
            ctrl.selectGroupMemberFromStatusItem(group: groupName, member: memberName)
            self.refreshPopoverCard(controller: ctrl)
        }
        popoverCardView.onPopUpGroupMenu = { [weak self] _, anchor in
            guard let self, let ctrl = self.mainWindowController else { return }
            self.presentNodePickerMenu(from: anchor, controller: ctrl)
        }
        popoverCardView.onSelectGlobalNode = { [weak self] nodeName in
            guard let self, let ctrl = self.mainWindowController else { return }
            ctrl.selectGlobalPolicyFromStatusItem(nodeName)
            self.refreshPopoverCard(controller: ctrl)
        }
        popoverCardView.onToggleEnhancedMode = { [weak self] in
            guard let self, let ctrl = self.mainWindowController else { return }
            ctrl.toggleEnhancedModeFromStatusItem()
            self.refreshPopoverCard(controller: ctrl)
        }
        popoverCardView.onToggleSystemProxy = { [weak self] in
            guard let self, let ctrl = self.mainWindowController else { return }
            ctrl.toggleSystemProxyFromStatusItem()
            self.refreshPopoverCard(controller: ctrl)
        }
        popoverCardView.onClickThemeSelector = { [weak self] anchor in
            guard let self else { return }
            self.presentThemePickerMenu(from: anchor)
        }
        popoverCardView.onOpenConsole = { [weak self] in
            guard let self else { return }
            self.closeStatusPopover()
            self.mainWindowController?.revealFromStatusItem()
        }
        popoverCardView.onQuitApp = { [weak self] in
            self?.closeStatusPopover()
            NSApp.terminate(nil)
        }

        statusItem = item
        syncStatusPopoverAppearance()
        if let controller = mainWindowController {
            refreshPopoverCard(controller: controller)
        }
        startTrafficTicker()
    }

    @objc private func toggleStatusPopover(_ sender: AnyObject?) {
        if statusPopover.isShown {
            closeStatusPopover()
        } else {
            openStatusPopover()
        }
    }

    private func openStatusPopover() {
        guard let button = statusItem?.button, let controller = mainWindowController else { return }
        syncStatusPopoverAppearance()
        refreshPopoverCard(controller: controller)
        statusPopover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        statusPopover.contentViewController?.view.window?.makeKey()
        if outsideClickMonitor == nil {
            outsideClickMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
                guard let self, self.statusPopover.isShown else { return }
                self.closeStatusPopover()
            }
        }
    }

    private func closeStatusPopover() {
        if statusPopover.isShown {
            statusPopover.performClose(nil)
        }
        if let monitor = outsideClickMonitor {
            NSEvent.removeMonitor(monitor)
            outsideClickMonitor = nil
        }
    }

    func popoverDidClose(_ notification: Notification) {
        if let monitor = outsideClickMonitor {
            NSEvent.removeMonitor(monitor)
            outsideClickMonitor = nil
        }
    }

    private func refreshPopoverCard(controller: MainWindowController) {
        let snap = controller.statusItemTelemetrySnapshot(
            uploadRate: lastUploadBytesPerSecond,
            downloadRate: lastDownloadBytesPerSecond
        )
        let isRunning = controller.isEngineActive || controller.isEnhancedModeActive
        let subtitle: String
        if snap.enhancedMode && snap.systemProxy {
            subtitle = "增强模式 (utun) + 系统代理"
        } else if snap.enhancedMode {
            subtitle = "增强模式 (utun) · 原生 TUN 数据面已就绪"
        } else if snap.systemProxy {
            subtitle = "系统代理 · 本地监听已就绪"
        } else if isRunning {
            subtitle = "本地代理监听运行中 · \(snap.modeTitle)"
        } else {
            subtitle = "代理引擎已停止 · 点击下方开关启动"
        }

        let sectionLeft: String
        let sectionAction: String
        let rawGroups = controller.statusItemPolicyGroups
        let rawGlobalNodes = controller.statusItemGlobalNodeItems
        let activeGlobalName = controller.statusItemGlobalPolicy

        switch controller.statusItemOutboundMode {
        case .rule:
            sectionLeft = "🧭 策略组分流配置（共 \(rawGroups.count) 组 · 点击展开）"
            sectionAction = controller.isStatusItemTestingNodes ? "测速中…" : "⚡ 全部测速"
        case .proxy:
            sectionLeft = "🌐 全局节点选举（共 \(rawGlobalNodes.count) 节点 · 直选）"
            sectionAction = controller.isStatusItemTestingNodes ? "测速中…" : "⚡ 全节点测速"
        case .direct:
            sectionLeft = "全局直连"
            sectionAction = "DIRECT"
        }

        let groupModels: [StatusBarModeAdaptiveListView.PolicyGroupEntryModel] = rawGroups.map { g in
            let eff = g.selectedMember ?? g.effectiveMember ?? "DIRECT"
            let effItem = controller.statusItemNodeItem(named: eff)
            return .init(
                name: g.name,
                kindBadge: g.kindBadgeText,
                effectiveMember: eff,
                latencyMillis: effItem.latencyMillis,
                members: g.members,
                selectedMember: g.selectedMember
            )
        }

        let globalModels: [StatusBarModeAdaptiveListView.GlobalNodeEntryModel] = rawGlobalNodes.map { nd in
            let latText: String
            let tier: Int
            switch nd.latency {
            case .success(let ms):
                latText = "\(ms) ms"
                tier = ms < 160 ? 1 : (ms < 400 ? 2 : 3)
            case .testing:
                latText = "测速中…"
                tier = 0
            case .queued:
                latText = "排队中"
                tier = 0
            case .failed, .unavailable:
                latText = "超时"
                tier = 3
            case .untested:
                latText = "待测速"
                tier = 0
            }
            return .init(
                name: nd.name,
                protocolTag: nd.protocolTag,
                latencyText: latText,
                latencyTier: tier,
                isSelected: nd.name == activeGlobalName,
                isOptimal: nd.isOptimal
            )
        }

        let theme = HajimiThemeCenter.shared.currentTheme
        popoverCardView.update(with: .init(
            isRunning: isRunning,
            subtitle: subtitle,
            latencyMillis: snap.activeNodeLatencyMillis,
            activeMode: controller.statusItemOutboundMode,
            sectionHeaderLeft: sectionLeft,
            sectionHeaderAction: sectionAction,
            groups: groupModels,
            globalNodes: globalModels,
            isEnhancedMode: snap.enhancedMode,
            isSystemProxy: snap.systemProxy,
            themeBadgeText: theme.displayTitle
        ))
        let targetSize = popoverCardView.preferredPopoverSize
        if popoverCardView.frame.size != targetSize {
            popoverCardView.frame = NSRect(origin: .zero, size: targetSize)
        }
        if statusPopover.contentSize != targetSize {
            statusPopover.contentSize = targetSize
        }
        statusItem?.button?.toolTip = "哈基米 · \(controller.statusItemSummary)"
    }

    private static func attributedGroupRowTitle(groupName: String, effective: String, latencyMillis: Int?) -> NSAttributedString {
        let attr = NSMutableAttributedString()
        attr.append(NSAttributedString(string: "\(groupName)：", attributes: [
            .font: NSFont.systemFont(ofSize: 13, weight: .medium),
            .foregroundColor: themePrimaryTextColor()
        ]))
        attr.append(NSAttributedString(string: effective, attributes: [
            .font: NSFont.systemFont(ofSize: 13, weight: .semibold),
            .foregroundColor: HajimiAppearance.accentText
        ]))
        if let ms = latencyMillis {
            attr.append(NSAttributedString(string: "  \(ms) ms", attributes: [
                .font: NSFont.monospacedDigitSystemFont(ofSize: 11, weight: .semibold),
                .foregroundColor: HajimiAppearance.uploadAccent
            ]))
        }
        return attr
    }

    private func updateOpenNodePickerMenuInPlace(controller: MainWindowController) {
        let testAllTitle = controller.isStatusItemTestingNodes ? "⚡ 正在测试节点延迟…" : "⚡ 一键测速全部节点"
        globalTestAllItem.title = testAllTitle
        globalTestAllView.configure(
            title: testAllTitle,
            image: Self.menuSymbol("bolt.horizontal.circle", tint: HajimiAppearance.accentText)
        )

        let groupTestTitle = controller.isStatusItemTestingNodes ? "⚡ 正在测速本组节点…" : "⚡ 测速本组节点"
        let groupsByName = Dictionary(uniqueKeysWithValues: controller.statusItemPolicyGroups.map { ($0.name, $0) })

        for (groupName, entry) in policyGroupMenuEntries {
            entry.testItem.title = groupTestTitle
            entry.testView.configure(
                title: groupTestTitle,
                image: Self.menuSymbol("bolt.horizontal.circle", tint: HajimiAppearance.accentText)
            )
            guard let group = groupsByName[groupName] else { continue }
            let effective = group.effectiveMember ?? "DIRECT"
            let effectiveNodeItem = controller.statusItemNodeItem(named: effective)
            entry.item.title = "\(group.name)：\(effective)"
            entry.item.attributedTitle = Self.attributedGroupRowTitle(
                groupName: group.name,
                effective: effective,
                latencyMillis: effectiveNodeItem.latencyMillis
            )

            let optimalMember = controller.statusItemOptimalMemberName(forGroup: group.name)
            let memberNodeItems = group.members.map {
                controller.statusItemNodeItem(named: $0, optimalName: optimalMember)
            }
            let measureFont = NSFont.systemFont(ofSize: 13, weight: .semibold)
            let maxNameWidth = memberNodeItems.map {
                ($0.name as NSString).size(withAttributes: [.font: measureFont]).width
            }.max() ?? 120
            let tabLocation = max(144.0, ceil(maxNameWidth) + 22.0)

            for (offset, nodeItem) in memberNodeItems.enumerated() {
                let menuIndex = offset + 3
                guard entry.submenu.items.indices.contains(menuIndex) else { continue }
                let item = entry.submenu.items[menuIndex]
                let isSelected = group.selectedMember == nodeItem.name
                    || (group.selectedMember == nil && group.effectiveMember == nodeItem.name)
                item.state = isSelected ? .on : .off
                item.attributedTitle = Self.attributedNodeMenuTitle(
                    node: nodeItem, isSelected: isSelected, tabLocation: tabLocation)
            }
        }

        if controller.statusItemOutboundMode == .proxy {
            let globalNodes = controller.statusItemGlobalNodeItems
            let activeNodeName = controller.statusItemGlobalPolicy
            let measureFont = NSFont.systemFont(ofSize: 13, weight: .semibold)
            let maxNameWidth = globalNodes.map {
                ($0.name as NSString).size(withAttributes: [.font: measureFont]).width
            }.max() ?? 120
            let tabLocation = max(144.0, ceil(maxNameWidth) + 22.0)
            for (offset, node) in globalNodes.enumerated() {
                let menuIndex = offset + 2
                guard nodePickerMenu.items.indices.contains(menuIndex) else { continue }
                let item = nodePickerMenu.items[menuIndex]
                let isSelected = (activeNodeName == node.name)
                item.state = isSelected ? .on : .off
                item.attributedTitle = Self.attributedNodeMenuTitle(
                    node: node, isSelected: isSelected, tabLocation: tabLocation)
            }
        }
    }

    private func presentNodePickerMenu(from anchorView: NSView, controller: MainWindowController) {
        syncStatusPopoverAppearance()
        nodePickerMenu.removeAllItems()

        let activeMode = controller.statusItemOutboundMode
        if activeMode == .rule {
            let groups = controller.statusItemPolicyGroups
            let groupTestTitle = controller.isStatusItemTestingNodes ? "⚡ 正在测速本组节点…" : "⚡ 测速本组节点"
            if !groups.isEmpty {
                for group in groups {
                    let entry: PolicyGroupMenuEntry
                    if let existing = policyGroupMenuEntries[group.name] {
                        entry = existing
                    } else {
                        let groupName = group.name
                        entry = PolicyGroupMenuEntry(
                            groupName: groupName,
                            onTestGroup: { [weak self] in
                                guard let self, let ctrl = self.mainWindowController else { return }
                                ctrl.testGroupNodesFromStatusItem(group: groupName)
                                self.updateOpenNodePickerMenuInPlace(controller: ctrl)
                            },
                            target: self,
                            defaultAction: #selector(selectPolicyGroupDefault(_:))
                        )
                        policyGroupMenuEntries[groupName] = entry
                    }
                    entry.submenu.appearance = statusPopover.appearance
                    entry.testItem.title = groupTestTitle
                    entry.testView.resetHoverState()
                    entry.testView.configure(
                        title: groupTestTitle,
                        image: Self.menuSymbol("bolt.horizontal.circle", tint: HajimiAppearance.accentText)
                    )

                    let effective = group.effectiveMember ?? "DIRECT"
                    let effectiveNodeItem = controller.statusItemNodeItem(named: effective)
                    entry.item.title = "\(group.name)：\(effective)"
                    entry.item.attributedTitle = Self.attributedGroupRowTitle(
                        groupName: group.name,
                        effective: effective,
                        latencyMillis: effectiveNodeItem.latencyMillis
                    )
                    entry.item.image = Self.groupSymbol(for: group.kind)

                    let firstMember = group.members.first ?? "DIRECT"
                    entry.defaultItem.title = group.kind == .select
                        ? "配置默认（\(firstMember)）"
                        : "自动（按\(group.kindBadgeText)策略 · 默认 \(firstMember)）"
                    entry.defaultItem.state = group.selectedMember == nil ? .on : .off

                    while entry.submenu.items.count > 3 {
                        entry.submenu.removeItem(at: entry.submenu.items.count - 1)
                    }
                    let optimalMember = controller.statusItemOptimalMemberName(forGroup: group.name)
                    let memberNodeItems = group.members.map {
                        controller.statusItemNodeItem(named: $0, optimalName: optimalMember)
                    }
                    let measureFont = NSFont.systemFont(ofSize: 13, weight: .semibold)
                    let maxNameWidth = memberNodeItems.map {
                        ($0.name as NSString).size(withAttributes: [.font: measureFont]).width
                    }.max() ?? 120
                    let tabLocation = max(144.0, ceil(maxNameWidth) + 22.0)
                    entry.submenu.minimumWidth = max(276, tabLocation + 132)

                    for nodeItem in memberNodeItems {
                        let memberItem = NSMenuItem(title: nodeItem.name, action: #selector(selectPolicyGroupMember(_:)), keyEquivalent: "")
                        memberItem.target = self
                        memberItem.representedObject = ["group": group.name, "member": nodeItem.name]
                        let isSelected = group.selectedMember == nodeItem.name
                            || (group.selectedMember == nil && group.effectiveMember == nodeItem.name)
                        memberItem.state = isSelected ? .on : .off
                        memberItem.attributedTitle = Self.attributedNodeMenuTitle(
                            node: nodeItem, isSelected: isSelected, tabLocation: tabLocation)
                        entry.submenu.addItem(memberItem)
                    }
                    nodePickerMenu.addItem(entry.item)
                }
                nodePickerMenu.minimumWidth = 288
                nodePickerMenu.popUp(positioning: nil, at: NSPoint(x: anchorView.bounds.minX, y: anchorView.bounds.maxY + 4), in: anchorView)
                return
            }
        }

        if activeMode == .direct {
            let directInfo = NSMenuItem(title: "当前为全部直连模式（所有流量直接连接）", action: nil, keyEquivalent: "")
            directInfo.isEnabled = false
            nodePickerMenu.addItem(directInfo)
            nodePickerMenu.popUp(positioning: nil, at: NSPoint(x: anchorView.bounds.minX, y: anchorView.bounds.maxY + 4), in: anchorView)
            return
        }

        let testTitle = controller.isStatusItemTestingNodes ? "⚡ 正在测试节点延迟…" : "⚡ 一键测速全部节点"
        globalTestAllItem.title = testTitle
        globalTestAllView.resetHoverState()
        globalTestAllView.configure(
            title: testTitle,
            image: Self.menuSymbol("bolt.horizontal.circle", tint: HajimiAppearance.accentText)
        )
        nodePickerMenu.addItem(globalTestAllItem)
        nodePickerMenu.addItem(globalTestSeparator)

        let globalNodes = controller.statusItemGlobalNodeItems
        let activeNodeName = controller.statusItemGlobalPolicy
        let measureFont = NSFont.systemFont(ofSize: 13, weight: .semibold)
        let maxNameWidth = globalNodes.map {
            ($0.name as NSString).size(withAttributes: [.font: measureFont]).width
        }.max() ?? 120
        let tabLocation = max(144.0, ceil(maxNameWidth) + 22.0)
        nodePickerMenu.minimumWidth = max(276, tabLocation + 132)

        for node in globalNodes {
            let item = NSMenuItem(title: node.name, action: #selector(selectGlobalPolicy(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = node.name
            let isSelected = (activeNodeName == node.name)
            item.state = isSelected ? .on : .off
            item.attributedTitle = Self.attributedNodeMenuTitle(
                node: node, isSelected: isSelected, tabLocation: tabLocation)
            nodePickerMenu.addItem(item)
        }

        nodePickerMenu.popUp(positioning: nil, at: NSPoint(x: anchorView.bounds.minX, y: anchorView.bounds.maxY + 4), in: anchorView)
    }

    private func presentThemePickerMenu(from anchorView: NSView) {
        syncStatusPopoverAppearance()
        uiThemeMenu.removeAllItems()
        let current = HajimiThemeCenter.shared.currentTheme
        openThemeSettingsItem.image = Self.menuSymbol("slider.horizontal.3", tint: HajimiAppearance.accentText)
        uiThemeMenu.addItem(openThemeSettingsItem)
        uiThemeMenu.addItem(.separator())

        for theme in HajimiThemeCenter.shared.allThemes {
            let item = NSMenuItem(title: theme.displayTitle, action: #selector(selectUIThemeFromStatusItem(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = theme.id
            let isSelected = (theme.id == current.id)
            item.state = isSelected ? .on : .off

            let attr = NSMutableAttributedString()
            let dotColor = HajimiUITheme.color(fromHex: theme.accentHex)
            attr.append(NSAttributedString(string: "● ", attributes: [
                .font: NSFont.systemFont(ofSize: 12, weight: .bold),
                .foregroundColor: dotColor
            ]))
            attr.append(NSAttributedString(string: theme.displayTitle, attributes: [
                .font: NSFont.systemFont(ofSize: 12.5, weight: isSelected ? .bold : .medium),
                .foregroundColor: isSelected ? HajimiAppearance.accentText : Self.themePrimaryTextColor()
            ]))
            attr.append(NSAttributedString(string: "  \(theme.category)", attributes: [
                .font: NSFont.systemFont(ofSize: 10.5, weight: .regular),
                .foregroundColor: Self.themeSecondaryTextColor()
            ]))
            item.attributedTitle = attr
            uiThemeMenu.addItem(item)
        }

        uiThemeMenu.popUp(positioning: nil, at: NSPoint(x: 0, y: anchorView.bounds.maxY + 4), in: anchorView)
    }

    private func startTrafficTicker() {
        trafficTicker?.invalidate()
        let timer = Timer(timeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.refreshTrafficReadout()
        }
        RunLoop.main.add(timer, forMode: .common)
        trafficTicker = timer
        refreshTrafficReadout()
    }

    private static let emptyTrafficTitle = NSAttributedString(string: "")
    private static let trafficTitleAttributes: [NSAttributedString.Key: Any] = {
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = .right
        paragraph.lineSpacing = -3
        paragraph.maximumLineHeight = 9
        return [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 9, weight: .regular),
            .foregroundColor: NSColor.controlTextColor,
            .paragraphStyle: paragraph,
            .baselineOffset: -1,
        ]
    }()

    private func refreshTrafficReadout() {
        guard let button = statusItem?.button else { return }
        guard let controller = mainWindowController else {
            if !lastTrafficReadoutKey.isEmpty {
                lastTrafficReadoutKey = ""
                button.attributedTitle = Self.emptyTrafficTitle
            }
            return
        }
        let rate = controller.statusItemTrafficRate()
        lastUploadBytesPerSecond = rate.upload
        lastDownloadBytesPerSecond = rate.download
        if statusPopover.isShown {
            refreshPopoverCard(controller: controller)
        }
        let uploadText = TrafficRateFormatter.compact(bytesPerSecond: rate.upload)
        let downloadText = TrafficRateFormatter.compact(bytesPerSecond: rate.download)
        let themeID = HajimiThemeCenter.shared.currentTheme.id
        let key = "\(uploadText)|\(downloadText)|\(themeID)"
        guard key != lastTrafficReadoutKey else { return }
        lastTrafficReadoutKey = key
        button.attributedTitle = Self.menuBarInlineTrafficTitle(upload: uploadText, download: downloadText)
    }

    static func configureTrafficButton(_ button: NSButton) {
        button.imagePosition = .imageLeading
    }

    /// Single-line menu bar readout matching the UI showcase: ` ⚡ ▲ 2.4M ▼ 38.6M`
    static func menuBarInlineTrafficTitle(upload: String, download: String) -> NSAttributedString {
        let font = NSFont.monospacedDigitSystemFont(ofSize: 11, weight: .bold)
        let accent = HajimiAppearance.accentText
        let upColor = HajimiAppearance.uploadAccent

        let result = NSMutableAttributedString()
        result.append(NSAttributedString(string: " ⚡ ", attributes: [
            .font: NSFont.systemFont(ofSize: 10.5, weight: .bold),
            .foregroundColor: accent
        ]))
        result.append(NSAttributedString(string: "▲ \(upload) ", attributes: [
            .font: font,
            .foregroundColor: upColor
        ]))
        result.append(NSAttributedString(string: "▼ \(download)", attributes: [
            .font: font,
            .foregroundColor: accent
        ]))
        return result
    }

    static func trafficTitle(upload: String, download: String) -> NSAttributedString {
        return NSAttributedString(string: "↑ \(upload)\n↓ \(download)", attributes: trafficTitleAttributes)
    }

    static func validateTrafficTitleMetrics() throws {
        struct Failure: LocalizedError {
            let text: String
            var errorDescription: String? { "状态栏速率显示自检失败：\(text)" }
        }
        let title = trafficTitle(upload: "999K", download: "12M")
        let size = title.size()
        guard title.string.split(separator: "\n").count == 2 else {
            throw Failure(text: "速率标题应为两行")
        }
        guard size.height <= 22 else {
            throw Failure(text: "两行高度为 \(size.height) 点，超过菜单栏的 22 点")
        }
        guard size.height >= 12 else {
            throw Failure(text: "两行高度仅 \(size.height) 点，行距过紧会互相压盖")
        }
        guard size.width <= 60 else {
            throw Failure(text: "宽度为 \(size.width) 点，菜单栏占位过宽")
        }
    }

    private static func attributedNodeMenuTitle(node: StatusProxyNodeItem, isSelected: Bool,
                                                tabLocation: CGFloat = 156) -> NSAttributedString {
        let paragraph = NSMutableParagraphStyle()
        paragraph.tabStops = [NSTextTab(textAlignment: .left, location: tabLocation)]
        paragraph.defaultTabInterval = tabLocation

        let result = NSMutableAttributedString()
        let nameFont = NSFont.systemFont(ofSize: 13, weight: isSelected ? .semibold : .regular)
        let nameColor = isSelected ? HajimiAppearance.accentText : themePrimaryTextColor()
        result.append(NSAttributedString(string: node.name, attributes: [
            .font: nameFont,
            .foregroundColor: nameColor,
            .paragraphStyle: paragraph
        ]))

        let badgeText: String
        let badgeColor: NSColor
        switch node.latency {
        case .success(let ms):
            let digits = String(ms)
            let padded = String(repeating: "\u{2007}", count: max(0, 3 - digits.count)) + digits
            badgeText = "\t● \(padded) ms"
            if ms < 180 {
                badgeColor = HajimiAppearance.accentText
            } else if ms < 500 {
                badgeColor = .systemOrange
            } else {
                badgeColor = .systemRed
            }
        case .testing:
            badgeText = "\t◌ 测速中…"
            badgeColor = HajimiAppearance.uploadAccent
        case .queued:
            badgeText = "\t◌ 排队中"
            badgeColor = themeSecondaryTextColor()
        case .failed:
            badgeText = "\t● 超时"
            badgeColor = .systemRed
        case .unavailable(let failure):
            badgeText = "\t● \(NodeLatency.unavailable(failure).text)"
            badgeColor = .systemOrange
        case .untested:
            badgeText = "\t· 未测速"
            badgeColor = themeSecondaryTextColor().withAlphaComponent(0.7)
        }

        let latFont = NSFont.monospacedDigitSystemFont(ofSize: 11.5, weight: .semibold)
        result.append(NSAttributedString(string: badgeText, attributes: [
            .font: latFont,
            .foregroundColor: badgeColor,
            .paragraphStyle: paragraph
        ]))
        if node.isOptimal {
            let optFont = NSFont.systemFont(ofSize: 10, weight: .bold)
            result.append(NSAttributedString(string: " ★最优", attributes: [
                .font: optFont,
                .foregroundColor: HajimiAppearance.accentText,
                .paragraphStyle: paragraph
            ]))
        }
        return result
    }

    private static func groupSymbol(for kind: PolicyGroupKind) -> NSImage? {
        switch kind {
        case .select: return menuSymbol("square.stack.3d.up", tint: HajimiAppearance.accentText)
        case .urlTest, .smart: return menuSymbol("bolt.badge.clock", tint: HajimiAppearance.uploadAccent)
        case .fallback: return menuSymbol("arrow.triangle.swap", tint: HajimiAppearance.accentText)
        case .loadBalance: return menuSymbol("circle.grid.cross", tint: HajimiAppearance.indigoAccent)
        case .subnet: return menuSymbol("network", tint: HajimiAppearance.accentText)
        }
    }

    @objc private func openThemeSettingsFromStatusItem() {
        closeStatusPopover()
        mainWindowController?.revealThemeSettingsFromStatusItem()
    }
    @objc private func selectUIThemeFromStatusItem(_ sender: NSMenuItem) {
        guard let themeID = sender.representedObject as? String else { return }
        HajimiThemeCenter.shared.selectTheme(id: themeID)
        if let ctrl = mainWindowController {
            refreshPopoverCard(controller: ctrl)
        }
    }
    @objc private func testAllNodesFromStatusItem() {
        guard let ctrl = mainWindowController else { return }
        ctrl.testAllNodesFromStatusItem()
        refreshPopoverCard(controller: ctrl)
    }
    @objc private func selectGlobalPolicy(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String, let ctrl = mainWindowController else { return }
        ctrl.selectGlobalPolicyFromStatusItem(name)
        refreshPopoverCard(controller: ctrl)
    }
    @objc private func selectPolicyGroupDefault(_ sender: NSMenuItem) {
        guard let info = sender.representedObject as? [String: String],
              let group = info["group"], let ctrl = mainWindowController else { return }
        ctrl.selectGroupMemberFromStatusItem(group: group, member: nil)
        refreshPopoverCard(controller: ctrl)
    }
    @objc private func selectPolicyGroupMember(_ sender: NSMenuItem) {
        guard let info = sender.representedObject as? [String: String],
              let group = info["group"],
              let member = info["member"], let ctrl = mainWindowController else { return }
        ctrl.selectGroupMemberFromStatusItem(group: group, member: member)
        refreshPopoverCard(controller: ctrl)
    }
}

if CommandLine.arguments.contains("--self-test") ||
   CommandLine.arguments.contains("--native-dataplane-self-test") ||
   CommandLine.arguments.contains("--ingress-security-self-test") ||
   CommandLine.arguments.contains("--network-optimization-self-test") ||
   CommandLine.arguments.contains("--proxy-performance-smoke-test") {
    if let failure = ProxyEngine.listenerLifecycleSelfTest() {
        FileHandle.standardError.write(Data("FAILED: \(failure)\n".utf8))
        Darwin.exit(1)
    }
    print("Hajimi unified C11/C++ engine self-test passed")
    Darwin.exit(0)
}

NetworkProcessResources.prepareOpenFileLimit()
let application = NSApplication.shared
let delegate = AppDelegate()
application.delegate = delegate
application.setActivationPolicy(.regular)
application.run()
